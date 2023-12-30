use std::ops::Range;
use regex::Regex;
use lazy_static::lazy_static;
use zxcvbn::zxcvbn;
use crate::backend::models::NewUser;


lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$"
    ).unwrap();
    }

fn is_valid_email(email: &str) -> bool {
    EMAIL_REGEX.is_match(email)
}

fn do_passwords_match(password1: &str, password2: &str) -> bool {
    password1 == password2
}

/// Check if the password length is valid
/// If range is none, the default range is 8..64
fn is_password_length_valid(password: &str, range: Option<Range<usize>>) -> bool {
    let range = range.unwrap_or(8..64);
    return range.contains(&(password.len()));
}

fn get_password_strength(password: &str) -> u8 {
    zxcvbn(password, &[]).unwrap().score()
}

fn get_password_warning(password: &str) -> String {
    let binding = zxcvbn(password, &[]).unwrap();
    let feedback = binding.feedback();
    if let Some(feedback) = feedback {
        feedback.warning().map_or_else(|| String::new(), |warning| warning.to_string())
    } else {
        String::new() // Handle the case where feedback is None
    }
}

pub fn validate_user(user: &NewUser) -> Result<(), String> {
    if !is_valid_email(&user.email) {
        return Err("Invalid email format.".to_string());
    }
    if !do_passwords_match(&user.password, &user.password2) {
        return Err("Passwords do not match.".to_string());
    }
    if !is_password_length_valid(&user.password, None) {
        return Err("Password length is not valid.".to_string());
    }
    if get_password_strength(&user.password) < 2 {
        return Err("Password is too weak.".to_string());
    }
    Ok(())
}
