use anyhow::Result;
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use serde::{Serialize};
use chrono::{Utc, Duration};

pub enum Role {
    Access,
    Refresh,
}

#[derive(Serialize)]
struct Claims {
    sub: String,  // Subject
    iat: i64,     // Issued At
    exp: i64,     // Expiration
    iss: String,  // Issuer
}

fn create_jwt(user_id: &str, issuer: &str, rsa_pri_key: &[u8], validity: i64) -> Result<String, jsonwebtoken::errors::Error> {
    let issued_at = Utc::now();
    let expiration = issued_at + Duration::seconds(validity);

    let claims = Claims {
        sub: user_id.to_owned(),
        iat: issued_at.timestamp(),
        exp: expiration.timestamp(),
        iss: issuer.to_owned(),
    };

    encode(&Header::new(Algorithm::RS256), &claims, &EncodingKey::from_rsa_pem(rsa_pri_key)?)
}

/// Verify the validity of a JWT accordingly to its role (access or refresh)
/// Return the email contained in the JWT if its valid
/// Return an error if the JWT is invalid
pub fn verify<T: Into<String>>(jwt: T, role: Role) -> Result<String> {
    todo!()
}
