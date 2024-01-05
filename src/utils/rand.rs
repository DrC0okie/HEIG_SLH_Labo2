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
