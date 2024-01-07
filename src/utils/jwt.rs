use std::collections::HashSet;
use anyhow::{anyhow, Result};
use jsonwebtoken::{encode, Header, EncodingKey, Validation, decode, DecodingKey};
use serde::{Deserialize, Serialize};
use std::env;
use chrono::{Duration, Utc};
use crate::consts;

/// Role of the JWT
/// * `Access` - token used for accessing secured resources.
/// * `Refresh` - token used for generating a new access token.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(PartialEq)]
pub enum Role {
    Access,
    Refresh,
}

/// A struct representing the claims to be encoded in a JWT.
/// * `iss` - A String representing the issuer of the token.
/// * `iat` - An i64 UNIX timestamp representing the time the token was issued.
/// * `exp` - An i64 UNIX timestamp representing the time the token will expire.
/// * `email` - A String containing the user's email address.
/// * `role` - A Role indicating the token's purpose.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    iat: i64,
    exp: i64,
    email: String,
    role: Role,
}

/// Creates a JWT with the specified email, role, and lifetime.
/// # Arguments
/// * `email` - Reference to a string slice representing the email of the user.
/// * `role` - Role enum value specifying the role of the token (Access or Refresh).
/// * `secret_key` - String slice containing the secret key used for encoding the JWT.
/// * `lifetime` - Duration representing the lifetime of the token. If None, a default duration based on the role.
/// # Returns
/// * `Ok(String)` - String containing the JWT on success.
/// * `Err(jsonwebtoken::errors::Error)` - Error if the JWT creation fails.
pub fn create_jwt(email: &str, role: Role, secret_key: &str, lifetime: Option<Duration>) -> Result<String, jsonwebtoken::errors::Error> {
    let issued_at = Utc::now();
    let expiration = issued_at + lifetime.unwrap_or_else(|| Duration::seconds(match role {
        Role::Access => consts::ACCESS_EXPIRATION,
        Role::Refresh => consts::REFRESH_EXP,
    } as i64));

    // Set the claims
    let claims = Claims {
        iss: consts::JWT_ISSUER.to_owned(),
        iat: issued_at.timestamp(),
        exp: expiration.timestamp(),
        email: email.to_owned(),
        role,
    };

    // Encode the JWT
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret_key.as_ref())).map_err(Into::into)
}

/// Verifies the validity of a JWT according to its role and returns the email contained within the token.
/// # Arguments
/// * `jwt` - A generic type T that can be converted into a String, representing the JWT to be verified.
/// * `role` - A Role enum value specifying the expected role of the token.
/// * `secret_key` - A string slice containing the secret key used for decoding and validating the JWT.
/// # Returns
/// * `Ok(String)` - A string containing the user's email if the JWT is valid.
/// * `Err(anyhow::Error)` - An error if the JWT verification fails or if there's a role mismatch.
pub fn verify<T: Into<String>>(jwt: T, role: Role, secret_key: &str) -> Result<String> {
    let token = jwt.into();

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

/// Retrieves the secret key used for JWT encoding and decoding from the environment.
/// # Returns
/// * `Ok(String)` - A string containing the secret key if found.
/// * `Err(String)` - An error message if the JWT_SECRET_KEY is not found in the environment variables.
pub fn get_secret_key() -> Result<String, String> {
    match env::var(consts::ENV_KEY_NAME) {
        Ok(key) => Ok(key),
        Err(_) => Err("JWT_SECRET_KEY not found in .env file".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts;
    use std::{env, thread};

    #[test]
    fn test_get_secret_key() {
        dotenv::dotenv().ok();
        let key = get_secret_key();
        assert!(key.is_ok(), "Secret key should be retrieved successfully");
    }

    #[test]
    fn test_create_jwt_valid() {
        dotenv::dotenv().ok();
        let email = "test@example.com";
        let jwt = create_jwt(email, Role::Access, get_secret_key().unwrap().as_str(), None);
        assert!(jwt.is_ok(), "JWT creation should succeed with valid parameters");
    }

    #[test]
    fn test_verify_jwt_valid() {
        dotenv::dotenv().ok();
        let email = "test@example.com";
        let jwt = create_jwt(email, Role::Access, get_secret_key().unwrap().as_str(), None);
        assert!(jwt.is_ok(), "JWT creation should succeed with valid parameters");

        let verification = verify(jwt.unwrap(), Role::Access, get_secret_key().unwrap().as_str());
        assert!(verification.is_ok(), "JWT verification should succeed with valid token: {}", verification.err().unwrap());
    }

    #[test]
    fn test_verify_jwt_role_mismatch() {
        dotenv::dotenv().ok();
        let email = "test@example.com";
        let jwt = create_jwt(email, Role::Access, get_secret_key().unwrap().as_str(), None);
        assert!(jwt.is_ok(), "JWT creation should succeed with valid parameters");

        let verification = verify(jwt.unwrap(), Role::Refresh, get_secret_key().unwrap().as_str());
        assert!(verification.is_err(), "JWT verification should fail with role mismatch");
    }

    #[test]
    fn test_verify_jwt_expired() {
        dotenv::dotenv().ok();
        let email = "test@example.com";
        let jwt = create_jwt(email, Role::Access, get_secret_key().unwrap().as_str(), Some(Duration::seconds(1)));
        assert!(jwt.is_ok(), "JWT creation should succeed with valid parameters");

        thread::sleep(std::time::Duration::from_secs(2)); // assuming the token expires immediately
        let verification = verify(jwt.unwrap(), Role::Access, get_secret_key().unwrap().as_str());
        assert!(verification.is_err(), "Expired JWT should not be verified successfully");
    }

    #[test]
    fn test_verify_jwt_incorrect_secret_key() {
        dotenv::dotenv().ok();
        let email = "test@example.com";
        let jwt = create_jwt(email, Role::Access, get_secret_key().unwrap().as_str(), None);
        assert!(jwt.is_ok(), "JWT creation should succeed with valid parameters");

        env::set_var(consts::ENV_KEY_NAME, "incorrect_secret_key");
        let verification = verify(jwt.unwrap(), Role::Access, "invalid key");
        assert!(verification.is_err(), "JWT with incorrect secret key should not be verified successfully");
    }

    #[test]
    fn test_verify_jwt_malformed_token() {
        dotenv::dotenv().ok();
        let malformed_token = "not.a.real.token";
        let verification = verify(malformed_token, Role::Access, get_secret_key().unwrap().as_str());
        assert!(verification.is_err(), "Malformed JWT should not be verified successfully");
    }
}
