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
use crate::{consts, HBS, database as DB, utils, email, backend};

pub async fn register(Json(user): Json<backend::models::NewUser>) -> axum::response::Result<StatusCode> {
    info!("Attempting to register new user");

    validate_new_user(&user)?;
    let hash = hash_user_password(&user.password)?;
    let token = create_jwt(&user.email, utils::jwt::Role::Verification)?;

    let exists = DB::user::exists(&user.email).unwrap_or_else(|e| {
        error!("{}", e);
        false
    });

    let (body, subject) = prepare_email_content(&token, exists)?;
    send_email(&user.email, &subject, &body)?;

    // Only add the user to the DB if everything else succeeded
    add_user_and_token(&user.email, &hash, &token)?;

    info!("New user registration successful");
    Ok(StatusCode::OK)
}

pub async fn verify(Path(token): Path<String>) -> Redirect {
    info!("Verify account");
    let msg = urlencoding::encode("Invalid or expired verification link");

    // Consume the token
    if let Err(e) = DB::token::consume(token.clone()).map_err(|e| e.to_string()) {
        error!("Token consumption error: {}", e);
        return Redirect::to(&*format!("/?verify=failed&message={}", &msg));
    }

    // Verify JWT
    let mail = match utils::jwt::verify(token, utils::jwt::Role::Verification) {
        Ok(email) => email.clone(),
        Err(e) => {
            error!("JWT verification error: {}", e);
            return Redirect::to(&*format!("/?verify=failed&message={}", &msg));
        }
    };

    // Update user's verified status
    if let Err(e) = DB::user::verify(&mail) {
        error!("Failed to set user as verified: {}", e);
        return Redirect::to("/?verify=failed");
    }

    info!("User successfully verified");
    Redirect::to("/?verify=ok")
}

pub async fn login(Json(user_login): Json<backend::models::UserLogin>) -> axum::response::Result<Json<backend::models::Token>> {
    info!("Login user");

    let exists = DB::user::exists(&user_login.email).unwrap_or_else(|_| {false});
    let verified = DB::user::verified(&user_login.email).unwrap_or_else(|_| {false});
    let token = create_jwt(&user_login.email, utils::jwt::Role::Refresh)?;
    let user = DB::user::get(&user_login.email);
    let valid_credentials = check_valid_credentials(user, &user_login.password)?;

    if !exists { return unauthorized("User does not exist in the DB"); }
    info!("User exists in the DB");

    if !verified { return unauthorized("User is not verified"); }
    info!("User is verified");

    if !valid_credentials { return unauthorized("Invalid credentials"); }
    info!("User credentials are valid, login successful");

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

/// Validates a new user's input.
/// # Arguments
/// * `user` - A reference to a `NewUser` struct containing the user's details.
/// # Returns
/// * `Ok(())` if the input is valid.
/// * `Err(axum::response::Result<StatusCode>)` if validation fails, with an appropriate HTTP status code.
fn validate_new_user(user: &backend::models::NewUser) -> Result<(), axum::response::Result<StatusCode>> {
    utils::input_validation::validate_user(user).map_err(|e| {
        error!("Validation error: {}", e);
        Err(axum::response::IntoResponse::into_response((StatusCode::BAD_REQUEST, e)).into())
    }).map(|_| {
        info!("User input is valid");
        ()
    })
}

/// Hashes a user's password.
/// # Arguments
/// * `password` - A string slice representing the user's password.
/// # Returns
/// * `Ok(String)` containing the hashed password on success.
/// * `Err(axum::response::Result<StatusCode>)` on failure, with an internal server error status code.
fn hash_user_password(password: &str) -> Result<String, axum::response::Result<StatusCode>> {
    utils::hashing::hash_password(password.as_bytes()).map_err(|e| {
        internal_error(format!("Hashing error: {}", e).as_str())
    }).map(|hash| {
        info!("User password hashed");
        hash
    })
}

/// Generates a JWT used for verifying a user's email address.
/// # Arguments
/// * `email` - The email address of the user for whom the JWT is being created.
/// # Returns
/// * `Ok(String)` containing the JWT on success.
/// * `Err(axum::response::Result<StatusCode>)` on failure, with an internal server error status code.
fn create_jwt(email: &str, role: utils::jwt::Role) -> Result<String, axum::response::Result<StatusCode>> {
    let role_name = format!("{:?}", &role);
    utils::jwt::create_jwt(email, role).map_err(|e| {
        internal_error(format!("JWT creation error: {}", e).as_str())
    }).map(|jwt| {
        info!("{:?} token created", role_name);
        jwt
    })
}

/// Attempts to create a new user in the database with the provided email and hashed password.
/// If successful, it then adds a verification token associated with the user.
/// # Arguments
/// * `email` - A string slice representing the user's email address.
/// * `password_hash` - A string slice representing the hashed password of the user.
/// * `token` - A string slice representing the verification token to be added to the database.
/// # Returns
/// * `Ok(())` - Indicates that both the user and token were successfully added to the database.
/// * `Err(axum::response::Result<StatusCode>)` - Returns an internal server error response in case
///   of failure to add either the user or the token to the database. The error response includes
///   a detailed error message for debugging purposes.
fn add_user_and_token(email: &str, password_hash: &str, token: &str) -> Result<(), axum::response::Result<StatusCode>> {
    DB::user::create(email, password_hash).map_err(|e| {
        internal_error(format!("Failed to create user: {}", e).as_str())
    }).map(|_| ()).and(DB::token::add(email, token, std::time::Duration::from_secs(consts::VERIFICATION_EXP)).map_err(|e| {
        internal_error(format!("Failed to add token to DB: {}", e).as_str())
    }).map(|_| ())).map(|_| ()).map(|_| {
        info!("User and token added to the DB");
        ()
    })
}

/// Checks if a user's password matches the hashed password in the database.
/// Ff the user is none (i.e. the user doesn't exist), the dummy hash is used to prevent timing attacks.
/// # Arguments
/// * `password_hash` - The hashed password of the user to be verified.
/// * `password` - The plaintext password to verify.
/// # Returns
/// * `Ok(bool)` - `true` if the password matches the hash, `false` otherwise.
/// * `Err(axum::response::Result<StatusCode>)` - An error response in case of failure.
fn check_valid_credentials(user: Option<DB::user::User>, password: &str) -> Result<bool, axum::response::Result<StatusCode>> {
    let hash = match user {
        None => utils::hashing::DUMMY_HASH.to_string(),
        Some(u) => u.hash,
    };

    utils::hashing::verify_password(hash.as_str(), password.as_bytes()).map_err(|e| {
        internal_error(format!("Error during password verification: {}", e).as_str())
    })
}

/// Prepares the content of the email to be sent to the user.
/// # Arguments
/// * `token` - Used to generate the verification URL.
/// * `exists` - A boolean indicating whether the user already exists in the DB.
/// # Returns
/// * `Ok((String, String))` - A tuple containing the body and subject of the email.
/// * `Err(axum::response::Result<StatusCode>)` - An error response in case of failure.
fn prepare_email_content(token: &str, exists: bool) -> Result<(String, String), axum::response::Result<StatusCode>> {
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
    Ok((body, subject))
}

/// Sends an email to the user with a link to verify their account.
/// # Arguments
/// * `email` - The email address of the user to be verified.
/// * `subject` - The subject of the email.
/// * `body` - The body of the email.
/// # Returns
/// * `Ok(())` - Indicates successful sending of the email.
/// * `Err(axum::response::Result<StatusCode>)` - An error response in case of failure.
fn send_email(email: &str, subject: &str, body: &str) -> Result<(), axum::response::Result<StatusCode>> {
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

/// Returns an unauthorized response and logs the error message as info.
/// # Arguments
/// * `log_msg` - A string slice containing a message to be logged.
/// # Returns
/// * `Err(axum::response::Result<StatusCode>)` - An error response with an unauthorized status code.
fn unauthorized(log_msg: &str) -> axum::response::Result<Json<backend::models::Token>> {
    let err_msg = "Login failed";
    info!("{}: {}",err_msg, log_msg);
    Err(axum::response::IntoResponse::into_response((StatusCode::UNAUTHORIZED, err_msg)).into())
}
