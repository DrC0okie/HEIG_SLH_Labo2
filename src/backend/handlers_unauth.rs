use axum::Json;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use axum::extract::Path;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use log::{debug, error, info, trace};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tower_sessions::Session;
use uuid::Uuid;
use crate::utils::rand::rand_base64;
use crate::{consts, HBS, database as DB, utils, email, backend};
use crate::utils::hashing::verify_password;
use crate::utils::input_validation::validate_user;
use crate::utils::jwt::get_secret_key;
use crate::utils::jwt::create_jwt;

/// Registers a new user in the database and sends a verification email.
/// # Arguments
/// * `user` - A `NewUser` struct containing the user's email and password.
/// # Returns
/// * `Ok(StatusCode)` - Indicates that the user was successfully registered.
/// * `Err(axum::response::Result<StatusCode>)` - An error response in case of failure.
pub async fn register(Json(user): Json<backend::models::NewUser>) -> axum::response::Result<StatusCode> {
    info!("Attempting to register new user");

    // Input validation on the password and email
    validate_user(&user).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let hash = utils::hashing::hash_password(&user.password.as_bytes()).map_err(|_| {
        internal_error("Failed to hash the password")
    })?;

    // Generate a random verification token
    let otp = rand_base64();

    let exists = DB::user::exists(&user.email).map_err(|e| {
        internal_error(format!("Failed to check if user exists: {}", e).as_str())
    })?;

    send_email(&user.email, &prepare_email_content(&otp, exists))?;

    if exists {
        return Ok(StatusCode::OK);
    }

    // Add the user to the DB
    DB::user::create(&user.email, &hash).map_err(|e| {
        internal_error(format!("Failed to create user: {}", e).as_str())
    })?;

    // Add the token to the DB
    DB::token::add(&user.email, &otp, std::time::Duration::from_secs(consts::VERIFICATION_EXP)).map_err(|e| {
        internal_error(format!("Failed to add token to DB: {}", e).as_str())
    })?;

    info!("New user registration successful");
    Ok(StatusCode::OK)
}

/// Verifies a user's account by consuming the verification token and setting the user's verified status to true.
/// # Arguments
/// * `token` - A string slice representing the verification token.
/// # Returns
/// * `Redirect` - A redirect to the index page with a message indicating whether the verification was successful.
/// * `Err(axum::response::Result<StatusCode>)` - An error response in case of failure.
pub async fn verify(Path(token): Path<String>) -> Redirect {
    info!("Verify account");
    let msg = urlencoding::encode("Invalid or expired verification link");

    // Consume the token
    let email = match DB::token::consume(token) {
        Ok(email) => email,
        Err(e) => {
            error!("Token consumption error: {}", e);
            return Redirect::to(&*format!("/?verify=failed&message={}", &msg));
        }
    };

    // Update user's verified status
    match DB::user::verify(&email) {
        Ok(true) => {},
        Ok(false) => return Redirect::to("/?verify=failed"),
        Err(e) => {
            error!("Failed to set user as verified: {}", e);
            return Redirect::to("/?verify=failed");
        }
    };

    info!("User successfully verified");
    Redirect::to("/?verify=ok")
}

/// Logs a user in in a time constant manner.
/// # Arguments
/// * `user_login` - A `UserLogin` struct containing the user's email and password.
/// # Returns
/// * `Ok(Json<Token>)` - A JSON object containing the JWT.
/// * `Err(axum::response::Result<StatusCode>)` - An error response in case of failure.
pub async fn login(Json(user_login): Json<backend::models::UserLogin>) -> axum::response::Result<Json<backend::models::Token>> {
    info!("Attempting to log a user in");

    // Input validation on the email
    utils::input_validation::is_email_valid(&user_login.email).map_err(|e| {
        axum::response::IntoResponse::into_response((StatusCode::BAD_REQUEST, e))
    })?;

    // Input length validation on the password
    utils::input_validation::is_password_length_valid(&user_login.password, None).map_err(|e| {
        axum::response::IntoResponse::into_response((StatusCode::BAD_REQUEST, e))
    })?;

    let exists = DB::user::exists(&user_login.email).unwrap_or_else(|e| {
        error!("{}", e);
        false
    });

    let verified = DB::user::verified(&user_login.email).unwrap_or_else(|e| {
        error!("{}", e);
        false
    });

    let hash = match DB::user::get(&user_login.email) {
        None => utils::hashing::DUMMY_HASH.to_string(),
        Some(u) => u.hash,
    };

    let password_ok = verify_password(hash.as_str(), &user_login.password.as_bytes()).unwrap_or_else(|_| false);

    if !exists || !verified || !password_ok {
        info!("Login failed");
        return Err(axum::response::IntoResponse::into_response((StatusCode::UNAUTHORIZED, "Login failed")).into());
    }

    let key = get_secret_key().unwrap();
    let token = create_jwt(&user_login.email, utils::jwt::Role::Refresh, key.as_str(), None).map_err(|e| {
        error!("JWT creation error: {}", e);
        axum::response::IntoResponse::into_response(StatusCode::INTERNAL_SERVER_ERROR)
    })?;

    info!("Login successful");
    Ok(Json::from(backend::models::Token { token }))
}

/// Serve index page
/// If the user is logged, add a anti-CSRF token to the password change form
pub async fn home(
    session: Session,
    user: Option<backend::middlewares::AccessUser>,
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
pub async fn email(Path(email): Path<String>) -> axum::response::Result<Json<Vec<DB::email::Email>>> {
    let emails = DB::email::get(&email).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(emails.into())
}

pub async fn logout(jar: CookieJar) -> (CookieJar, Redirect) {
    let jar = jar.remove(Cookie::from("access"));
    (jar, Redirect::to("/"))
}

pub async fn login_page() -> impl IntoResponse {
    Html(HBS.render("login", &Some(())).unwrap())
}

/// Prepares the content of the email to be sent to the user.
/// # Arguments
/// * `token` - Used to generate the verification URL.
/// * `exists` - A boolean indicating whether the user already exists in the DB.
/// # Returns
/// * `(String, String)` - A tuple containing the body and subject of the email.
fn prepare_email_content(token: &str, exists: bool) -> (String, String) {
    let (body, subject) = match exists {
        true => {
            ("Someone tried to register an account with your email address.".to_owned(),
             "Attempted registration".to_owned())
        }
        false => {
            (format!("Please click on the following link to verify your account: {}",
                     email::get_verification_url(token)),
             "Account Verification".to_owned())
        }
    };

    info!("Email content prepared");
    (body, subject)
}

/// Sends an email to the user with a link to verify their account.
/// # Arguments
/// * `email` - The email address of the user to be verified.
/// * `subject` - The subject of the email.
/// * `body` - The body of the email.
/// # Returns
/// * `Ok(())` - Indicates successful sending of the email.
/// * `Err(axum::response::Result<StatusCode>)` - An error response in case of failure.
fn send_email(email: &str, (subject, body): &(String, String)) -> Result<(), axum::response::Result<StatusCode>> {
    email::send_mail(email, subject, body).map_err(|_| {
        internal_error("Failed to send email")
    }).map(|_| {
        info!("Email sent");
        ()
    })
}

/// Returns an internal server error response and logs the error message as error.
/// # Arguments
/// * `log_msg` - A string slice containing a message to be logged.
/// # Returns
/// * `Err(axum::response::Result<StatusCode>)` - An error response with an internal server error status code.
fn internal_error(log_msg: &str) -> axum::response::Result<StatusCode> {
    let err_msg = "Internal server error, something went wrong";
    error!("{}", log_msg);
    Err(axum::response::IntoResponse::into_response((StatusCode::INTERNAL_SERVER_ERROR, err_msg)).into())
}
