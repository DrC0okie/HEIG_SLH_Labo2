use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct NewUser {
    pub email: String,
    pub password: String,
    pub password2: String,
}

#[derive(Serialize, Deserialize)]
pub struct Token {
    pub token: String
}

#[derive(Deserialize)]
pub struct UserLogin {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangePassword {
    pub old_password: String,
    pub password: String,
    pub password2: String,
    pub csrf: String,
}
