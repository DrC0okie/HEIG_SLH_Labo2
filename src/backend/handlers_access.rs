use axum::Json;
use http::StatusCode;
use log::info;
use tower_sessions::Session;
use crate::backend::middlewares::AccessUser;
use crate::backend::models::ChangePassword;

pub async fn change_password (
    session: Session,
    user: AccessUser,
    Json(parameters): Json<ChangePassword>
) -> axum::response::Result<StatusCode> {
    info!("Changing user's password");

    // Check that the anti-CSRF token isn't expired
    let token_expiration = session.get::<i64>("csrf_expiration").or(Err(StatusCode::INTERNAL_SERVER_ERROR))?.ok_or(StatusCode::BAD_REQUEST)?;
    if token_expiration < time::OffsetDateTime::now_utc().unix_timestamp() {
        info!("Anti-CSRF token expired");
        Err((StatusCode::BAD_REQUEST, "Anti-CSRF token expired"))?;
    }

    // Compare the anti-CSRF token saved with the given one
    let token = session.get::<String>("csrf")
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::BAD_REQUEST)?;
    if token != parameters.csrf {
        info!("Anti-CSRF tokens don't match");
        Err((StatusCode::BAD_REQUEST, "Anti-CSRF tokens don't match"))?;
    }

    // TODO : Check the parameters then update the DB with the new password
    return Err((StatusCode::BAD_REQUEST, "Function 'change_password' not implemented").into());
}
