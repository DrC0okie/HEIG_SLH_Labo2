use std::fs::File;
use std::sync::{RwLock, RwLockWriteGuard};
use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use std::ops::Deref;
use serde::{Deserialize, Serialize};

pub mod user {
    use std::collections::HashMap;
    use std::sync::{RwLock, RwLockWriteGuard};
    use anyhow::{anyhow, Context, Result};
    use log::{info, trace, warn};
    use once_cell::sync::Lazy;
    use serde::{Serialize, Deserialize};

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct User {
        pub hash: String,
        pub verified: bool
    }

    type Db = HashMap<String, User>;
    static DB: Lazy<RwLock<Db>> = Lazy::new(Default::default); // Map email to user

    pub fn create(email: &str, hash: &str) -> Result<bool> {
        info!("Creating new user");

        let user = User {
            hash: hash.to_string(),
            verified: false,
        };
        
        let mut db  = DB.write().or(Err(anyhow!("DB poisoned")))?;

        if db.contains_key(email) {
            info!("User already exists");
            return Ok(false);
        }

        db.insert(email.to_string(), user);

        trace!("User created");
        save(db).ok();
        Ok(true)
    }
    pub fn get(email: &str) -> Option<User> {
        info!("Retrieve user from DB");
        DB.read().ok()?.get(email).cloned()
    }
    pub fn exists(email: &str) -> Result<bool> {
        info!("Check if user exists in DB");
        Ok(DB.read().or(Err(anyhow!("DB poisoned")))?.contains_key(email))
    }

    pub fn change_password(email: &str, new_hash: &str) -> Result<bool> {
        info!("Change password of user");
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;

        let user = match db.get_mut(email) {
            None => {
                trace!("User not found");
                return Ok(false)
            },
            Some(u) => u,
        };

        user.hash = new_hash.to_string();

        trace!("Password changed");
        Ok(true)
    }

    /// Flag a user as verified
    /// Returns false if the user does not exist or if it is already verified
    /// Returns true if everything is fine :)
    pub fn verify(email: &str) -> Result<bool> {
        info!("Flag user as verified");
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;

        let user = match db.get_mut(email) {
            None => {
                trace!("User doesn't exist");
                return Ok(false)
            },
            Some(u) => u,
        };
        if user.verified {
            warn!("User already verified");
            return Ok(false)
        }

        user.verified = true;

        trace!("User flagged as verified");
        save(db).ok();
        Ok(true)
    }
    
    pub fn verified(email: &str) -> Result<bool> {
        info!("Check if user is verified");
        Ok(get(email).context("User not found")?.verified)
    }

    pub fn load() -> Result<()> {
        super::load(&DB, "users.bincode")
    }
    fn save(db: RwLockWriteGuard<'_, Db>) -> Result<()> {
        super::save(db, "users.bincode")
    }
}

pub mod token {
    use std::{collections::HashMap, sync::RwLockWriteGuard};
    use std::sync::RwLock;
    use anyhow::{anyhow, bail, Result};
    use log::{info, trace};
    use once_cell::sync::Lazy;
    use serde::{Serialize, Deserialize};
    use crate::database::user;
    extern crate serde_millis;

    type Db = HashMap<String, Tokens>;
    static DB: Lazy<RwLock<Db>> = Lazy::new(Default::default); // token to email

    #[derive(Serialize, Deserialize)]
    struct Tokens {
        email : String, 
        #[serde(with = "serde_millis")]
        expiration : std::time::Instant
    }

    /// Add a token for a user
    /// The function checks if the user exists
    pub fn add(email: &str, token: &str, duration: std::time::Duration) -> Result<()> {
        info!("Add token for user");
        if !user::exists(email)? {
            trace!("User doesn't exist");
            bail!("Invalid user");
        }

        // Generate token
        let expiration = std::time::Instant::now() + duration;
        
        // Save token in DB
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;
        db.insert(token.to_string(), Tokens {email: email.to_string(), expiration });

        // Return token
        trace!("Token added");
        save(db).ok();
        Ok(())
    }

    /// Returns email linked to the token, only if :
    /// - Token exists in the DB
    /// - Token isn't expired
    /// - DB hasn't crashed
    pub fn consume(token: String) -> Result<String> {
        info!("Use token");
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;
        let entry = db.remove(&token).ok_or(anyhow!("Token not found"))?;

        if entry.expiration < std::time::Instant::now() {
            info!("Token expired");
            bail!("Token expired");
        }

        trace!("Token consumed, email returned");
        save(db).ok();
        Ok(entry.email)
    }

    fn save(db : RwLockWriteGuard<'_, Db>) -> Result<()> {
        super::save(db, "tokens.bincode")
    }
    pub fn load() -> Result<()> {
        super::load(&DB, "tokens.bincode")
    }
}

pub mod email {
    use std::collections::HashMap;
    use std::sync::{RwLock, RwLockWriteGuard};
    use anyhow::{anyhow, Result};
    use once_cell::sync::Lazy;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Serialize, Deserialize)]
    pub struct Email {
        pk: u64,
        to: String,
        subject: String,
        body: String,
    }
    #[derive(Default, Serialize, Deserialize)]
    struct Db {
        next_pk: u64,
        emails: HashMap<u64, Email>,
    }

    static DB: Lazy<RwLock<Db>> = Lazy::new(Default::default);

    pub fn add(to: &str, subject: &str, body: &str) -> Result<()> {
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;

        let pk = db.next_pk;
        db.next_pk += 1;
        let email = Email { pk, to: to.into(), subject: subject.into(), body: body.into() };

        db.emails.insert(pk, email);

        save(db)
    }
    pub fn get(to: &str) -> Result<Vec<Email>> {
        let db = DB.read().or(Err(anyhow!("DB poisoned")))?;

        Ok(db.emails
            .iter()
            .filter(|e| e.1.to == to)
            .map(|e| e.1.clone())
            .collect())
    }
    pub fn remove(pk: u64) -> Result<()> {
        let mut db = DB.write().or(Err(anyhow!("DB poisoned")))?;
        db.emails.remove(&pk);
        save(db)
    }
    fn save(db: RwLockWriteGuard<Db>) -> Result<()> {
        super::save(db, "emails.bincode")
    }
    pub fn load() -> Result<()> {
        super::load(&DB, "emails.bincode")
    }
}

fn save<T: Serialize>(db: RwLockWriteGuard<'_, T>, path: &str) -> Result<()> {
    let file = File::create(path)?;

    bincode::serialize_into(file, db.deref()).or(Err(anyhow!("Failed to serialize DB")))?;

    Ok(())
}

fn load<T: for<'de> Deserialize<'de>>(db: &RwLock<T>, path: &str) -> Result<()> {
    info!("Loading {path}");
    // Create path to file
    let file = File::open(path)
        .or_else(|e| {
            warn!("Failed to open DB file");
            debug!("Error : {e}");
            Err(e)
        })?;

    // Read content
    let db_content: T = bincode::deserialize_from(file)
        .or_else(|e| {
            warn!("Failed to deserialize email DB content");
            debug!("Deserialization error : {e}");
            Err(e)
        })?;

    // Open DB mutex and set content
    let mut db = db.write().or(Err(anyhow!("DB poisoned")))?;

    *db = db_content;

    Ok(())
}
