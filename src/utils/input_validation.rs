use std::ops::Range;
use regex::Regex;
use lazy_static::lazy_static;
use log::info;
use zxcvbn::zxcvbn;
use crate::backend::models::{NewUser};

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
pub fn is_email_valid(email: &str) -> Result<(), String> {
    if EMAIL_REGEX.is_match(email) {
        Ok(())
    } else {
        let msg = "Invalid email format";
        info!("{}", msg);
        Err(msg.to_string())
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
        let msg = "Passwords do not match.";
        info!("{}", msg);
        Err(msg.to_string())
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
        let msg = format!("Password length is not valid, must be between {} and {} characters.", range.start, range.end);
        info!("{}", msg);
        Err(msg.to_string())
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
    is_email_valid(&user.email)?;
    info!("Email input valid.");
    validate_passwords(&user.password, &user.password2)
}


pub fn validate_passwords(password: &str, password2: &str) -> Result<(), String> {
    do_passwords_match(password, password2)?;
    is_password_length_valid(password, None)?;

    let password_strength = get_password_strength(password);
    if password_strength < MIN_PASSWORD_STRENGTH {
        return Err("Password is too weak.".to_owned());
    }
    info!("Password input valid.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Ensure the function returns Ok(()) for a valid email.
    fn test_is_valid_email() {
        assert!(is_email_valid("test@example.com").is_ok());
    }

    #[test]
    ///Ensure the function returns an error for an invalid email.
    fn test_is_invalid_email() {
        assert!(is_email_valid("invalid-email").is_err());
    }

    #[test]
    /// Check if the function returns Ok(()) when passwords match.
    fn test_do_passwords_match() {
        assert!(do_passwords_match("password123", "password123").is_ok());
    }

    #[test]
    /// Check for an error when passwords don't match.
    fn test_non_matching_passwords() {
        assert!(do_passwords_match("password123", "different").is_err());
    }

    #[test]
    /// Check if the function returns Ok(()) when the password length is within the specified range.
    fn test_is_password_length_valid() {
        // Within the range
        assert!(is_password_length_valid("1234", Some(0..8)).is_ok());
        // At the start of the range
        assert!(is_password_length_valid("12345678", Some(8..64)).is_ok());
        // At the end of the range
        assert!(is_password_length_valid("1234567", Some(1..8)).is_ok());
        // inversed range
        assert!(is_password_length_valid("12345", Some(8..1)).is_err());
        // default range
        assert!(is_password_length_valid("12345678", None).is_ok());
        // out of range
        assert!(is_password_length_valid("12345678", Some(1..8)).is_err());
        // out of range
        assert!(is_password_length_valid("1", Some(2..8)).is_err());
    }

    #[test]
    /// Check if a valid user and passwords passes all validations.
    fn test_validate_user_and_passwords() {

        let too_short_pasword = "hello";
        let too_long_password = "myVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryLargePassword";
        let too_weak_password = "password123";
        let valid_password_1 = "MyFirstValidAndStrongAndBeautifulPassword";
        let valid_password_2 = "MySecondValidAndStrongAndBeautifulPassword";
        let valid_email_user = "valid@valid.ch";
        let invalid_email_user = "invalid";


        let password_too_short = NewUser {
            email: valid_email_user.to_string(),
            password: too_short_pasword.to_string(),
            password2: too_short_pasword.to_string(),
        };

        let password_too_long = NewUser {
            email: valid_email_user.to_string(),
            password: too_long_password.to_string(),
            password2: too_long_password.to_string(),
        };

        let password_does_not_match = NewUser {
            email: valid_email_user.to_string(),
            password: valid_password_1.to_string(),
            password2: valid_password_2.to_string(),
        };

        let invalid_email = NewUser {
            email: invalid_email_user.to_string(),
            password: valid_password_1.to_string(),
            password2: valid_password_1.to_string(),
        };

        let valid_email = NewUser {
            email: valid_email_user.to_string(),
            password: valid_password_1.to_string(),
            password2: valid_password_1.to_string(),
        };

        let password_too_weak = NewUser {
            email: valid_email_user.to_string(),
            password: too_weak_password.to_string(),
            password2: too_weak_password.to_string(),
        };

        //valid password
        assert!(validate_passwords(&valid_password_1, &valid_password_1).is_ok());

        // password too short
        assert!(validate_passwords(too_short_pasword, too_short_pasword).is_err());

        // password too long
        assert!(validate_passwords(too_long_password, too_long_password).is_err());

        // passwords do not match
        assert!(validate_passwords(valid_password_1, valid_password_2).is_err());

        //passwords too weak
        assert!(validate_passwords(too_weak_password, too_weak_password).is_err());

        //-----------NewUsers

        //user with valid email
        assert!(validate_user(&valid_email).is_ok());

        //user with valid email
        assert!(validate_user(&password_too_short).is_err());

        //user with password too long
        assert!(validate_user(&password_too_long).is_err());

        //user with passwords not matching
        assert!(validate_user(&password_does_not_match).is_err());

        //user with invalid email
        assert!(validate_user(&invalid_email).is_err());

        //user with password too weak
        assert!(validate_user(&password_too_weak).is_err());
    }
}
