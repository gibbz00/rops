mod core;
pub use core::RopsFileMetadata;

#[cfg(feature = "age")]
mod age;
#[cfg(feature = "age")]
pub use age::RopsFileAgeMetadata;
