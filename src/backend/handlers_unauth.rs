use axum::Json;
use crate::backend::models::{NewUser, UserLogin, Token};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use log::{debug, info, trace};
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

pub async fn register(Json(user): Json<NewUser>) -> axum::response::Result<StatusCode> {
    info!("Register new user");
    // Validate user input
    Input::validate_user(&user)
        .map_err(|e| {
            info!("Validation error: {}", e);
            (StatusCode::BAD_REQUEST, e)
        })?;

    // Hash the password
    let password_hash = hashing::hash_password(user.password.as_bytes())
        .map_err(|e| {
            info!("Hashing error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.")
        })?;

    // Create the user or set flag if already exists
    let already_exists = database::user::create(&user.email, &password_hash).is_err();

    // Create a JWT for email verification
    let token = jwt::create_jwt(&user.email, jwt::Role::Verification)
        .map_err(|e| {
            info!("JWT creation error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.")
        })?;

    // Add the token to the DB to ensure one-time usability
    database::token::add(&user.email, &token, std::time::Duration::from_secs(consts::VERIFICATION_EXPIRATION)) // 2 hours
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error."))?;

    // Prepare and send the email
    let (body, subject) = if already_exists {
        ("Someone tried to register an account with your email address.".to_owned(), "Attempted Registration Notice".to_owned())
    } else {
        (format!("Please click on the following link to verify your account: {}", email::get_verification_url(&token)), "Account Verification".to_owned())
    };

    email::send_mail(&user.email, &subject, &body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

pub async fn verify(Path(token): Path<String>) -> Redirect {
    info!("Verify account");

    // Step 1: Verify JWT
    match jwt::verify(&token, jwt::Role::Verification) {
        Ok(email) => {
            // Step 2: Consume the token
            match database::token::consume(token) {
                Ok(_) => {
                    // Step 3: Update user's verified status
                    if let Err(e) = database::user::verify(&email) {
                        info!("Failed to set user as verified: {}", e);
                        return Redirect::to("/?verify=failed");
                    }
                    Redirect::to("/?verify=ok")
                },
                Err(e) => {
                    info!("Token consumption error: {}", e);
                    Redirect::to("/?verify=failed")
                }
            }
        },
        Err(e) => {
            info!("JWT verification error: {}", e);
            Redirect::to("/?verify=failed")
        }
    }
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
