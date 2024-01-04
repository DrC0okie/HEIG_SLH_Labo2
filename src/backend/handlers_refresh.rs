use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use http::StatusCode;
use log::{error, info};
use crate::backend::middlewares::RefreshUser;
use crate::utils;

pub async fn get_access(user: RefreshUser, jar: CookieJar) -> axum::response::Result<CookieJar> {
    info!("Get access JWT from refresh JWT");

    // Create access JWT for the email from RefreshUser
    let jwt = utils::jwt::create_jwt(&user.email, utils::jwt::Role::Access)
        .map_err(|e| {
            error!("JWT creation error: {}", e);
            axum::response::IntoResponse::into_response(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

    // Add JWT to jar and set cookie parameters
    let cookie = Cookie::build(("access", jwt))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/");

    let jar = jar.add(cookie);

    Ok(jar)
}
