use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use log::info;
use crate::backend::middlewares::RefreshUser;

pub async fn get_access(user: RefreshUser, jar: CookieJar) -> axum::response::Result<CookieJar> {
    info!("Get access JWT from refresh JWT");
    // User's refresh token is already checked through the extractor RefreshUser
    // You can trust the email given in the parameter "user"

    let jwt: String; // TODO : Create access JWT for email in user

    // Add JWT to jar
    let cookie = Cookie::build(("access", jwt))
        // TODO : Optionally set cookie's parameters
        ;
    let jar = jar.add(cookie);

    Ok(jar)
}
