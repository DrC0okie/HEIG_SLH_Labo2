use anyhow::Result;
use log::{info, trace};
use crate::database;
use crate::HTTP_PORT;

pub fn send_mail(to: &str, subject: &str, body: &str) -> Result<()> {
    info!("Sending an email");

    database::email::add(to, subject, body)?;

    trace!("Email added");

    Ok(())
}
pub fn get_verification_url(token: &str) -> String {
    format!("http://127.0.0.1:{HTTP_PORT}/verify/{token}")
}
