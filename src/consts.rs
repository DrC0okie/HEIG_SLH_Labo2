pub const HTTP_PORT: u16 = 8080;
pub const ACCESS_EXPIRATION: i64 = 60; // 1 minute
pub const REFRESH_EXPIRATION: i64 = 60 * 60 * 2; // 2 hours
pub const JWT_ISSUER: &str = "king_auth";
pub const ENV_KEY_NAME: &str = "JWT_SECRET_KEY";