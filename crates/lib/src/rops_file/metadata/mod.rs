mod core;
pub use core::{RopsFileMetadata, RopsFileMetadataDecryptError};

mod last_modified;
pub use last_modified::LastModifiedDateTime;

mod state;
pub use state::{DecryptedMetadata, EncryptedMetadata, RopsMetadataState};

#[cfg(feature = "age")]
mod age;
#[cfg(feature = "age")]
pub use age::RopsFileAgeMetadata;
