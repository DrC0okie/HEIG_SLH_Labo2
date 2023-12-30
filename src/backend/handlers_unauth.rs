use axum::Json;
use crate::backend::models::{NewUser, UserLogin, Token};

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect};
use log::{debug, info, trace};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tower_sessions::Session;
use uuid::Uuid;
use crate::{database, HBS};
use crate::backend::middlewares::AccessUser;
use axum::extract::Path;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use crate::database::email::Email;

pub async fn register(Json(user): Json<NewUser>) -> axum::response::Result<StatusCode> {
    info!("Register new user");

    // TODO : Register a new user
    // TODO : Send confirmation email : send_mail(...).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    return Err((StatusCode::INTERNAL_SERVER_ERROR, "Function 'register' not implemented").into());
}
pub async fn verify(Path(token): Path<String>) -> Redirect {
    info!("Verify account");

    // TODO : Flag user's account as verified (with the given token)
    let verification: bool;

    match verification {
        true => Redirect::to("/?verify=ok"),
        _ => Redirect::to("/?verify=failed"),
    }
}
pub async fn login(Json(user_login): Json<UserLogin>) -> axum::response::Result<Json<Token>> {
    info!("Login user");

    return Err((StatusCode::INTERNAL_SERVER_ERROR, "Function 'login' not implemented").into());

    // TODO : Login user
    // TODO : Generate refresh JWT

    let jwt: String;
    Ok(Json::from(Token { token: jwt }))
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
            session.insert("csrf", token.clone()).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
            session.insert("csrf_expiration", expiration.unix_timestamp()).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

            Some(json!({"email": user.email, "token": token}))
        },
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
