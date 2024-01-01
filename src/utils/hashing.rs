use argon2::{Argon2, password_hash::{SaltString, PasswordHasher}};
use rand_core::OsRng;

/// Hashes a password using the Argon2 algorithm.
///
/// # Arguments
/// * `password` - A byte slice representing the user's password.
///
/// # Returns
/// * `Ok(String)` containing the hashed password. The hash includes the Argon2 parameters and salt.
/// * `Err(String)` containing an error message if the password hashing fails.
pub fn hash_password(password: &[u8]) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    match argon2.hash_password(password, &salt) {
        Ok(password_hash) => Ok(password_hash.to_string()),
        Err(e) => Err(e.to_string()),
    }
}