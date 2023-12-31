use std::collections::HashSet;
use anyhow::{anyhow, Result};
use jsonwebtoken::{encode, Header, EncodingKey, Validation, decode, DecodingKey};
use serde::{Deserialize, Serialize};
use std::env;
use chrono::{Duration, Utc};
use crate::consts;

/// Role of the JWT
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(PartialEq)]
pub enum Role {
    Access,
    Refresh,
    Verification,
}

/// Claims struct for JWT
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    iat: i64,
    exp: i64,
    email: String,
    role: Role,
}
/// Create a JWT with the given email and role
/// Return the JWT if its valid, otherwise return an error
pub fn create_jwt(email: &str, role: Role) -> Result<String, jsonwebtoken::errors::Error> {
    let issued_at = Utc::now();
    let expiration = issued_at + Duration::seconds(match role {
        Role::Access => {consts::ACCESS_EXPIRATION}
        Role::Refresh => {consts::REFRESH_EXPIRATION}
        Role::Verification => {consts::VERIFICATION_EXPIRATION}
    } as i64);

    // Set the claims
    let claims = Claims {
        iss: consts::JWT_ISSUER.to_owned(),
        iat: issued_at.timestamp(),
        exp: expiration.timestamp(),
        email: email.to_owned(),
        role,
    };

    // retrieve the secret key from the environment
    let secret_key = match env::var(consts::ENV_KEY_NAME) {
        Ok(key) => key,
        Err(_) => return Err(jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat)),
    };

    // Encode the JWT
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret_key.as_ref())).map_err(Into::into)
}

/// Verify the validity of a JWT accordingly to its role (access or refresh)
/// Return the email contained in the JWT if its valid, otherwise return an error
pub fn verify<T: Into<String>>(jwt: T, role: Role) -> Result<String> {
    let token = jwt.into();
    let secret_key = env::var(consts::ENV_KEY_NAME).expect("Key not found in .env file");

    // Set validation parameters
    let mut validation = Validation::default();
    let mut issuer_set = HashSet::new();
    issuer_set.insert(consts::JWT_ISSUER.to_owned());
    validation.iss = Some(issuer_set);

    // Decode and validate the JWT
    let token_data = decode::<Claims>(&token, &DecodingKey::from_secret(secret_key.as_ref()), &validation)
        .map_err(|e| anyhow!("JWT Verification failed: {}", e))?;

    if token_data.claims.role != role {
        return Err(anyhow!("Token role mismatch"));
    }

    Ok(token_data.claims.email)
}

