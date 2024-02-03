use rops::cryptography::{cipher::AES256GCM, hasher::SHA512};

pub type DefaultCipher = AES256GCM;
pub type DefaultHasher = SHA512;
