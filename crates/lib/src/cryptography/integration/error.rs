use thiserror::Error;

pub type IntegrationResult<T> = Result<T, IntegrationError>;

#[derive(Debug, Error)]
pub enum IntegrationError {
    #[error("{0} integration - encryption error: {1}")]
    Encryption(&'static str, String),
    #[error("{0} integration - decryption error: {1}")]
    Decryption(&'static str, String),
    #[error("unable to parse public key string: {0}")]
    PublicKeyParsing(String),
    #[error("unalbe to parse private key string: {0}")]
    PrivateKeyParsing(String),
    #[error("io error during encryption/decryption: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unable to convert bytes into a UTF-8 string")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

#[cfg(feature = "age")]
impl From<age::EncryptError> for IntegrationError {
    fn from(encrypt_error: age::EncryptError) -> Self {
        use crate::*;
        Self::Encryption(AgeIntegration::NAME, encrypt_error.to_string())
    }
}

#[cfg(feature = "age")]
impl From<age::DecryptError> for IntegrationError {
    fn from(decrypt_error: age::DecryptError) -> Self {
        use crate::*;
        Self::Decryption(AgeIntegration::NAME, decrypt_error.to_string())
    }
}
