mod core;
pub use core::RopsFileMetadata;

mod last_modified;
pub use last_modified::LastModifiedDateTime;

#[cfg(feature = "age")]
mod age;
#[cfg(feature = "age")]
pub use age::RopsFileAgeMetadata;
