use axum::Json;
use crate::backend::models::{NewUser, UserLogin, Token};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use log::{debug, error, info, trace};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tower_sessions::Session;
use uuid::Uuid;
use crate::{consts, database, HBS};
use crate::backend::middlewares::AccessUser;
use axum::extract::Path;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use crate::database::email::Email;
use crate::email;
use crate::utils::input_validation as Input;
use crate::utils::hashing;
use crate::utils::jwt;
const ERR_MSG: &str = "Internal server error, please retry";
pub async fn register(Json(user): Json<NewUser>) -> axum::response::Result<StatusCode> {
    info!("Attempting to register new user");

    validate_new_user(&user)?;
    let hash = hash_user_password(&user.password)?;
    let token = create_verification_jwt(&user.email)?;
    let (body, subject) = handle_user_creation(&user.email, &hash, &token)?;

    // Send the verification email
    email::send_mail(&user.email, &subject, &body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

pub async fn verify(Path(token): Path<String>) -> Redirect {
    info!("Verify account");
    let msg = urlencoding::encode("Invalid or expired verification link");

    // Consume the token
    if let Err(e) = database::token::consume(token.clone()).map_err(|e| e.to_string()) {
        error!("Token consumption error: {}", e);
        return Redirect::to(&*format!("/?verify=failed&message={}", &msg));
    }

    // Verify JWT
    let mail = match jwt::verify(token, jwt::Role::Verification) {
        Ok(email) => email.clone(),
        Err(e) => {
            info!("JWT verification error: {}", e);
            return Redirect::to(&*format!("/?verify=failed&message={}", &msg));
        }
    };

    // Update user's verified status
    if let Err(e) = database::user::verify(&mail) {
        error!("Failed to set user as verified: {}", e);
        return Redirect::to("/?verify=failed");
    }

    Redirect::to("/?verify=ok")
}


pub async fn login(Json(user_login): Json<UserLogin>) -> axum::response::Result<Json<Token>> {
    info!("Login user");

    return Err((StatusCode::INTERNAL_SERVER_ERROR, "Function 'login' not implemented").into());

    // TODO : Login user
    // TODO : Generate refresh JWT

    // let jwt: String;
    // Ok(Json::from(Token { token: jwt }))
}


/// Serve index page
/// If the user is logged, add a anti-CSRF token to the password change form
pub async fn home(
    session: Session,
    user: Option<AccessUser>,
) -> axum::response::Result<impl IntoResponse> {
    trace!("Serving home");

    // Create anti-CSRF token if the user is logged
    let infos = match user {
        Some(user) => {
            debug!("Add anti-CSRF token to home");

            // Generate anti-CSRF token
            let token = Uuid::new_v4().to_string();
            let expiration = OffsetDateTime::now_utc() + Duration::minutes(10);

            // Add token+exp to session
            session.insert("csrf", token.clone()).await.or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
            session.insert("csrf_expiration", expiration.unix_timestamp()).await.or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

            Some(json!({"email": user.email, "token": token}))
        }
        None => None, // Can't use user.map, async move are experimental
    };

    Ok(Html(HBS.render("index", &infos).unwrap()))
}

/// DEBUG/ADMIN endpoint
/// List pending emails to send
pub async fn email(Path(email): Path<String>) -> axum::response::Result<Json<Vec<Email>>> {
    let emails = database::email::get(&email).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(emails.into())
}

pub async fn logout(jar: CookieJar) -> (CookieJar, Redirect) {
    let jar = jar.remove(Cookie::from("access"));
    (jar, Redirect::to("/"))
}

pub async fn login_page() -> impl IntoResponse {
    Html(HBS.render("login", &Some(())).unwrap())
}

/// Validates a new user's input.
///
/// # Arguments
/// * `user` - A reference to a `NewUser` struct containing the user's details.
///
/// # Returns
/// * `Ok(())` if the input is valid.
/// * `Err(axum::response::Result<StatusCode>)` if validation fails, with an appropriate HTTP status code.
fn validate_new_user(user: &NewUser) -> Result<(), axum::response::Result<StatusCode>> {
    Input::validate_user(user).map_err(|e| {
        error!("Validation error: {}", e);
        Err(axum::response::IntoResponse::into_response((StatusCode::BAD_REQUEST, e)).into())
    })
}


/// Hashes a user's password.
///
/// # Arguments
/// * `password` - A string slice representing the user's password.
///
/// # Returns
/// * `Ok(String)` containing the hashed password on success.
/// * `Err(axum::response::Result<StatusCode>)` on failure, with an internal server error status code.

fn hash_user_password(password: &str) -> Result<String, axum::response::Result<StatusCode>> {
    hashing::hash_password(password.as_bytes()).map_err(|e| {
        error!("Hashing error: {}", e);
        Err(axum::response::IntoResponse::into_response((StatusCode::INTERNAL_SERVER_ERROR, ERR_MSG)).into())
    })
}

/// Generates a JWT used for verifying a user's email address.
///
/// # Arguments
/// * `email` - The email address of the user for whom the JWT is being created.
///
/// # Returns
/// * `Ok(String)` containing the JWT on success.
/// * `Err(axum::response::Result<StatusCode>)` on failure, with an internal server error status code.
fn create_verification_jwt(email: &str) -> Result<String, axum::response::Result<StatusCode>> {
    jwt::create_jwt(email, jwt::Role::Verification).map_err(|e| {
        error!("JWT creation error: {}", e);
        Err(axum::response::IntoResponse::into_response((StatusCode::INTERNAL_SERVER_ERROR, ERR_MSG)).into())
    })
}

/// It creates the user in the database and adds a token for email verification.
///
/// # Arguments
/// * `email` - The email address of the user.
/// * `password_hash` - The hashed password of the user.
/// * `token` - The JWT token for email verification.
///
/// # Returns
/// * `Ok((String, String))` containing the appropriate message and subject for the email to be sent.
/// * `Err(axum::response::Result<StatusCode>)` on failure, with an internal server error status code.
fn handle_user_creation(email: &str, password_hash: &str, token: &str) -> Result<(String, String), axum::response::Result<StatusCode>> {
    match database::user::create(email, password_hash) {
        Ok(true) => {
            info!("New user added to the DB");
            database::token::add(email, token, std::time::Duration::from_secs(consts::VERIFICATION_EXP))
                .map_err(|e| {
                    error!("Failed to add token: {}", e);
                    Err(axum::response::IntoResponse::into_response(StatusCode::INTERNAL_SERVER_ERROR).into())
                })?;
            info!("Token added in the DB for new user");

            Ok((format!("Please click on the following link to verify your account: {}",
                        email::get_verification_url(token)),
                "Account Verification".to_owned()))
        }
        Ok(false) => {
            info!("User already exists in the DB");
            Ok(("Someone tried to register an account with your email address.".to_owned(),
                "Attempted Registration Notice".to_owned()))
        }
        Err(e) => {
            error!("Failed to create user in DB: {}", e);
            Err(Err(axum::response::IntoResponse::into_response((StatusCode::INTERNAL_SERVER_ERROR, ERR_MSG)).into()))
        }
    }
}
