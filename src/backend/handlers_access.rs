use axum::Json;
use http::StatusCode;
use log::{error, info};
use tower_sessions::Session;
use crate::backend::middlewares::AccessUser;
use crate::backend::models::ChangePassword;
use crate::utils::input_validation::{validate_passwords, is_password_length_valid};
use crate::utils::hashing::{verify_password, hash_password, DUMMY_HASH};
use crate::{database as DB, email};

const ERR_MSG: &str = "Server error, something went wrong";

pub async fn change_password(
    session: Session,
    user: AccessUser,
    Json(parameters): Json<ChangePassword>,
) -> axum::response::Result<StatusCode> {
    info!("Changing user's password");

    // Check that the anti-CSRF token isn't expired
    let token_expiration = session.get::<i64>("csrf_expiration").await.or(Err(StatusCode::INTERNAL_SERVER_ERROR))?.ok_or(StatusCode::BAD_REQUEST)?;
    if token_expiration < time::OffsetDateTime::now_utc().unix_timestamp() {
        info!("Anti-CSRF token expired");
        Err((StatusCode::BAD_REQUEST, "Anti-CSRF token expired"))?;
    }

    // Compare the anti-CSRF token saved with the given one
    let token = session.get::<String>("csrf")
        .await.or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::BAD_REQUEST)?;
    if token != parameters.csrf {
        info!("Anti-CSRF tokens don't match");
        Err((StatusCode::BAD_REQUEST, "Anti-CSRF tokens don't match"))?;
    }

    // Input length validation on the old password (DoS)
    is_password_length_valid(&parameters.old_password, None).map_err(|_| {
        (StatusCode::BAD_REQUEST, "Old password is not valid")
    })?;

    // Input validation on the new passwords
    // We don't care if the old password is the same as the new one. In this case, the user is just stupid
    validate_passwords(&parameters.password, &parameters.password2).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Check that the old password is correct
    let old_hash = match DB::user::get(&user.email) {
        None => DUMMY_HASH.to_string(),
        Some(u) => u.hash,
    };

    match verify_password(old_hash.as_str(), &parameters.old_password.as_bytes()) {
        Ok(true) => {},
        Ok(false) => {return Err((StatusCode::BAD_REQUEST, "Old password is wrong").into())},
        Err(_) => {return Err((StatusCode::BAD_REQUEST, ERR_MSG).into())},
    };

    // Hash the new password
    let new_hash = hash_password(&parameters.password.as_bytes())
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ERR_MSG))?;

    // Send email to the user to notify that the password has been changed
    let subject = "Password changed";
    let body = "Your password has been changed. If you didn't do it, please contact us.";

    email::send_mail(&user.email, subject, body).map_err(|e| {
        error!("Error sending email: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, ERR_MSG)
    })?;

    // Update the DB
    match DB::user::change_password(&user.email, &new_hash){
        Ok(true) => Ok(StatusCode::OK),
        Ok(false) => {
            error!("User not found, this should never happen as the user is logged");
            Err((StatusCode::INTERNAL_SERVER_ERROR, ERR_MSG).into())
        },
        Err(e) => {
            error!("Error changing password: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, ERR_MSG).into())
        },
    }
}
