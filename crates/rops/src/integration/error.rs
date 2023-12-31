use std::ffi::OsString;

use thiserror::Error;

pub type IntegrationResult<T> = Result<T, IntegrationError>;

// TODO: place as inner error in an error type that always includes integration name
#[derive(Debug, Error)]
pub enum IntegrationError {
    #[error("encryption error: {0}")]
    Encryption(anyhow::Error),
    #[error("decryption error: {0}")]
    Decryption(anyhow::Error),
    #[error("unable to parse key id string: {0}")]
    KeyIdParsing(anyhow::Error),
    #[error("unnable to parse private key string: {0}")]
    PrivateKeyParsing(anyhow::Error),
    #[error("io error during encryption/decryption: {0}")]
    Io(#[from] std::io::Error),
    #[error("unable to convert bytes into a UTF-8 string")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("matched environment variable not valid UTF-8: {0:?}")]
    EnvVarNotUnicode(OsString),
    #[error("unable to retrieve any home directory from the operating system")]
    NoHomeDir,
}
