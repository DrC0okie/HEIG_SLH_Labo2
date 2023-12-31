use argon2::{Argon2, password_hash::{SaltString, PasswordHasher}};
use rand_core::OsRng;

pub fn hash_password(password: &[u8]) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    match argon2.hash_password(password, &salt) {
        Ok(password_hash) => Ok(password_hash.to_string()),
        Err(e) => Err(e.to_string()),
    }
}