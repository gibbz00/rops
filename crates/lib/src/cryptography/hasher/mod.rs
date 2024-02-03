mod core;
pub(crate) use core::Hasher;

#[cfg(feature = "sha2")]
mod sha512;
#[cfg(feature = "sha2")]
pub use sha512::SHA512;
