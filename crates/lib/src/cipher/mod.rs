mod core;
pub use core::Cipher;

mod variant;
pub use variant::CipherVariant;

#[cfg(feature = "aes-gcm")]
mod aes256_gcm;
#[cfg(feature = "aes-gcm")]
pub use aes256_gcm::AES256GCM;
