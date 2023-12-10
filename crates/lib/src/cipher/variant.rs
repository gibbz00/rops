use strum::{AsRefStr, EnumString};

use crate::*;

#[derive(Debug, PartialEq, AsRefStr, EnumString)]
pub enum CipherVariant {
    #[cfg(feature = "aes-gcm")]
    #[strum(serialize = "AES256_GCM")]
    AES256GCM,
}

impl CipherVariant {
    pub fn cipher(&self) -> &dyn Cipher {
        match self {
            #[cfg(feature = "aes-gcm")]
            CipherVariant::AES256GCM => &AES256GCM,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use crate::*;

        #[test]
        fn displays_aes256_gcm_cipher() {
            assert_eq!("AES256_GCM", CipherVariant::AES256GCM.as_ref())
        }

        #[test]
        fn parses_aes256_gcm_cipher() {
            assert_eq!(CipherVariant::AES256GCM, "AES256_GCM".parse::<CipherVariant>().unwrap())
        }
    }
}
