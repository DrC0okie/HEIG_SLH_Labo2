use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;

/// Creates a cryptographically secure, random string. The generated string is 32 characters long
/// and encoded in URL-safe Base64 format without padding.
/// # Returns
/// A `String` that is 32 characters long, URL-safe, and Base64-encoded.
pub fn rand_base64() -> String {
    // Using 24 bytes for a 32 character token
    let mut bytes = vec![0u8; 24];
    OsRng.fill_bytes(&mut bytes);

    // Encode the random bytes to URL-safe base64 without padding
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_base64_length() {
        let result = rand_base64();
        assert_eq!(result.len(), 32, "The length of the output should be 32 characters.");
    }

    #[test]
    fn test_rand_base64_url_safe_encoding() {
        let result = rand_base64();
        let is_url_safe = result.chars().all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".contains(c));
        assert!(is_url_safe, "The output should be URL-safe Base64 encoded.");
    }

    #[test]
    fn test_rand_base64_uniqueness() {
        let result1 = rand_base64();
        let result2 = rand_base64();
        assert_ne!(result1, result2, "Multiple calls should produce unique results.");
    }
}
