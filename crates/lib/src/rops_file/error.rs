use thiserror::Error;

use crate::*;

#[derive(Debug, Error)]
pub enum RopsFileEncryptError {
    #[error("invalid decrypted map format: {0}")]
    FormatToIntenrnalMap(#[from] FormatToInternalMapError),
    #[error("unable to retrieve data key: {0}")]
    DataKeyRetrieval(#[from] RopsFileMetadataDataKeyRetrievalError),
    #[error("unable to encrypt map: {0}")]
    MapEncryption(anyhow::Error),
    #[error("unable to encrypt metadata: {0}")]
    MetadataEncryption(anyhow::Error),
    #[error(transparent)]
    Integration(#[from] IntegrationError),
}

#[derive(Debug, Error)]
pub enum RopsFileDecryptError {
    #[error("invalid encrypted map format; {0}")]
    FormatToIntenrnalMap(#[from] FormatToInternalMapError),
    #[error("unable to decrypt map value: {0}")]
    DecryptValue(#[from] DecryptRopsValueError),
    #[error("unable to decrypt file metadata")]
    Metadata(#[from] RopsFileMetadataDecryptError),
    #[error("invalid MAC, computed {0}, stored {0}")]
    MacMismatch(String, String),
}
