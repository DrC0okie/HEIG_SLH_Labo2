use axum::async_trait;
use axum::extract::FromRequestParts;
use axum_extra::extract::CookieJar;
use http::request::Parts;
use http::{header, HeaderMap, StatusCode};
use log::{debug, info, trace};
use serde::Serialize;
use crate::utils::jwt;
use crate::utils::jwt::Role;

#[derive(Serialize)]
pub struct RefreshUser {
    pub(crate) email: String
}
#[derive(Serialize, Debug)]
pub struct AccessUser {
    pub(crate) email: String
}

#[async_trait]
impl<S> FromRequestParts<S> for RefreshUser
    where S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        trace!("Verify refresh JWT");

        // Retrieve JWT
        let jwt = get_jwt_from_headers(&parts.headers)
            .ok_or(StatusCode::BAD_REQUEST)?;

        // Verify JWT and retrieve email
        let email = jwt::verify(jwt, Role::Refresh)
            .or(Err(StatusCode::BAD_REQUEST))?;

        trace!("Refresh JWT validated from headers");
        Ok(Self { email })
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AccessUser
    where S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, s: &S) -> Result<Self, Self::Rejection> {
        info!("Retrieve and verify 'access' JWT from cookies");

        // Retrieve JWT from cookies
        let cookies = CookieJar::from_request_parts(parts, s)
            .await
            .expect("You lied to me. It was written Infallible"); // Flagged as Infallible
        let jwt_cookie = cookies
            .get("access")
            .ok_or_else(|| {
                trace!("Access JWT not found in the cookies");
                StatusCode::BAD_REQUEST
            })?;
        let jwt = jwt_cookie.value();

        // Validate cookie
        let email = jwt::verify(jwt, Role::Access)
            .or(Err(StatusCode::BAD_REQUEST))?;

        // Return validated email
        trace!("Access JWT retrieved, returning email");
        Ok(Self { email })
    }
}

fn get_jwt_from_headers(headers: &HeaderMap) -> Option<&str> {
    // Retrieve JWT from headers and parse its value to UTF-8 String
    let value = headers
        .get(header::AUTHORIZATION)
        .or_else(|| {
            trace!("Can't find field 'authorization' in headers");
            None
        })?
        .to_str()
        .ok()
        .or_else(|| {
            trace!("Failed to convert header's value to str");
            None
        })?;

    // Split value of header and check its format (format : 'Bearer: XXX')
    let fields: Vec<&str> = value.split(' ').collect();
    if fields.len() != 2 {
        debug!("Malformed value of authorization header");
        return None;
    }
    if fields[0] != "Bearer" {
        trace!("Malformed authorization header, first part isn't 'Bearer'");
        return None;
    }

    // Return extracted JWT
    Some(fields[1])
}
