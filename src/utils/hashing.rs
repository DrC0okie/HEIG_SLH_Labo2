use argon2::{Argon2, password_hash::{SaltString, PasswordHasher}, PasswordHash, PasswordVerifier};
use lazy_static::lazy_static;
use rand_core::OsRng;

// The dummy hash is used to prevent timing attacks.
lazy_static! {
    pub static ref DUMMY_HASH: String = hash_password(b"dummy").unwrap();
}

/// Hashes a password using the Argon2 algorithm.
/// # Arguments
/// * `password` - A byte slice representing the user's password.
/// # Returns
/// * `Ok(String)` containing the hashed password. The hash includes the Argon2 parameters and salt.
/// * `Err(String)` containing an error message if the password hashing fails.
pub fn hash_password(password: &[u8]) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);

    match Argon2::default().hash_password(password, &salt) {
        Ok(password_hash) => Ok(password_hash.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Verifies a plaintext password against a hashed password.
/// # Arguments
/// * `hashed_password` - The hashed password (including Argon2 parameters and salt).
/// * `password` - The plaintext password to verify.
/// # Returns
/// * `Ok(bool)` - `true` if the password matches the hash, `false` otherwise.
/// * `Err(String)` - An error message if the verification process fails.
pub fn verify_password(hashed_password: &str, password: &[u8]) -> Result<bool, String> {
    // Parse the string into PasswordHash
    let parsed_hash = PasswordHash::new(hashed_password)
        .map_err(|e| e.to_string())?;

    match Argon2::default().verify_password(password, &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false), // Password does not match
        Err(e) => Err(e.to_string()), // Other errors
    }
}