use std::ops::Range;
use regex::Regex;
use lazy_static::lazy_static;
use zxcvbn::zxcvbn;
use crate::backend::models::NewUser;

// Compile the email regex once and use it across function calls.
lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$"
    ).unwrap();
    }

pub const MIN_PASSWORD_STRENGTH: u8 = 3;

/// Validates the format of an email address.
///
/// # Arguments
/// * `email` - A string slice that holds the email address to validate.
///
/// # Returns
/// * `Ok(())` if the email format is valid,
/// * `Err(String)` with an error message if the format is invalid.
pub fn is_valid_email(email: &str) -> Result<(), String> {
    if EMAIL_REGEX.is_match(email) {
        Ok(())
    } else {
        Err("Invalid email format.".to_string())
    }
}

/// Checks if two provided passwords match.
///
/// # Arguments
/// * `password1` - First password string slice.
/// * `password2` - Second password string slice.
///
/// # Returns
/// * `Ok(())` if passwords match,
/// * `Err(String)` with an error message if they don't.
pub fn do_passwords_match(password1: &str, password2: &str) -> Result<(), String> {
    if password1 == password2 {
        Ok(())
    } else {
        Err("Passwords do not match.".to_string())
    }
}

/// Validates if the password length is within the specified range.
///
/// # Arguments
/// * `password` - Password to validate.
/// * `range` - Optional range for the password length. Defaults to 8..64 if None.
///
/// # Returns
/// * `Ok(())` if the password length is valid,
/// * `Err(String)` with an error message if it's not.
pub fn is_password_length_valid(password: &str, range: Option<Range<usize>>) -> Result<(), String> {
    let range = range.unwrap_or(8..64);
    if range.contains(&password.len()) {
        Ok(())
    } else {
        Err("Password length is not valid.".to_string())
    }
}

/// Computes the strength score of a password using zxcvbn.
///
/// # Arguments
/// * `password` - Password to evaluate.
///
/// # Returns
/// * A score representing the strength of the password.
pub fn get_password_strength(password: &str) -> u8 {
    zxcvbn(password, &[]).unwrap().score()
}

/// Validates a NewUser object by checking email format, password match, length, and strength.
///
/// # Arguments
/// * `user` - A reference to a NewUser object containing user registration details.
///
/// # Returns
/// * `Ok(())` if all validations pass,
/// * `Err(String)` with a specific error message if any validation fails.
pub fn validate_user(user: &NewUser) -> Result<(), String> {
    is_valid_email(&user.email)?;
    do_passwords_match(&user.password, &user.password2)?;
    is_password_length_valid(&user.password, None)?;

    let password_strength = get_password_strength(&user.password);
    if password_strength < MIN_PASSWORD_STRENGTH {
        return Err("Password is too weak.".to_owned());
    }

    Ok(())
}
