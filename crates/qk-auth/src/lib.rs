//! Stores the passphrase that encrypts QuietKeep's SSH identity in the desktop keyring
//! (GNOME Keyring or KWallet through the Secret Service API).

use base64::Engine;

const SERVICE: &str = "dev.quietwire.quietkeep";
const ACCOUNT: &str = "ssh-identity";

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("desktop keyring is not available: {0}")]
    Unavailable(String),
}

fn entry() -> Result<keyring::Entry, AuthError> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| AuthError::Unavailable(e.to_string()))
}

/// Returns the stored passphrase, if one exists.
pub fn stored_passphrase() -> Result<Option<String>, AuthError> {
    match entry()?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(AuthError::Unavailable(e.to_string())),
    }
}

/// Returns the stored passphrase, creating and storing a random 256-bit one if none exists.
pub fn passphrase() -> Result<String, AuthError> {
    if let Some(p) = stored_passphrase()? {
        return Ok(p);
    }
    let bytes: [u8; 32] = rand::random();
    let p = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
    entry()?.set_password(&p).map_err(|e| AuthError::Unavailable(e.to_string()))?;
    // Read back so a keyring that silently drops writes is detected before the key is encrypted.
    match stored_passphrase()? {
        Some(read) if read == p => Ok(p),
        _ => Err(AuthError::Unavailable("the keyring did not keep the passphrase".into())),
    }
}
