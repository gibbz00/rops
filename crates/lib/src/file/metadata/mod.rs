mod core;
pub use core::RopsFileMetadata;
pub(crate) use core::{RopsFileMetadataDataKeyRetrievalError, RopsFileMetadataDecryptError};

pub mod state;
pub(crate) use state::{DecryptedMetadata, EncryptedMetadata, RopsMetadataState};

pub mod integration;
pub(crate) use integration::*;

mod last_modified;
pub(crate) use last_modified::LastModifiedDateTime;

mod mac;
pub(crate) use mac::*;

mod partial_encryption;
pub use partial_encryption::PartialEncryptionConfig;
pub(crate) use partial_encryption::ResolvedPartialEncryption;
