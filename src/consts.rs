pub const HTTP_PORT: u16 = 8080;
pub const ACCESS_EXPIRATION: u64 = 60 * 10; // 10 minutes
pub const REFRESH_EXP: u64 = 60 * 60 * 24 * 30; // 30 days
pub const VERIFICATION_EXP: u64 = 60 * 60 * 2; // 2 hours
pub const JWT_ISSUER: &str = "king_auth";
pub const ENV_KEY_NAME: &str = "JWT_SECRET_KEY";