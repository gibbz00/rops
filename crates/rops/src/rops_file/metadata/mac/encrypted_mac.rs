use std::{marker::PhantomData, str::FromStr};

use derive_more::Display;

use crate::*;

#[derive(Display)]
#[display(fmt = "{}", "self.0")]
#[impl_tools::autoimpl(Debug, PartialEq)]
pub struct EncryptedMac<C: Cipher, H: Hasher>(pub(crate) EncryptedRopsValue<C>, pub(crate) PhantomData<H>);

// WORKAROUND: https://jeltef.github.io/derive_more/derive_more/from_str.html
// does not seem to support a #[fromstr] (as of 12/2023).
impl<C: Cipher, H: Hasher> FromStr for EncryptedMac<C, H> {
    type Err = <EncryptedRopsValue<C> as FromStr>::Err;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        str.parse().map(|encrypted_value| Self(encrypted_value, PhantomData))
    }
}

impl<C: Cipher, H: Hasher> EncryptedMac<C, H> {
    pub fn decrypt(self, data_key: &DataKey, last_modified_date_time: &LastModifiedDateTime) -> Result<Mac<H>, C::Error> {
        self.decrypt_impl(data_key, last_modified_date_time).map(|(mac, _)| mac)
    }

    #[allow(clippy::type_complexity)]
    pub fn decrypt_and_save_nonce(
        self,
        data_key: &DataKey,
        last_modified_date_time: &LastModifiedDateTime,
    ) -> Result<(Mac<H>, SavedMacNonce<C, H>), C::Error> {
        self.decrypt_impl(data_key, last_modified_date_time)
            .map(|(mac, nonce)| (mac.clone(), SavedMacNonce::new(mac, nonce)))
    }

    #[allow(clippy::type_complexity)]
    fn decrypt_impl(
        self,
        data_key: &DataKey,
        last_modified_date_time: &LastModifiedDateTime,
    ) -> Result<(Mac<H>, Nonce<C::NonceSize>), C::Error> {
        let mut in_place_buffer = Vec::from(self.0.data);
        C::decrypt(
            &self.0.nonce,
            data_key,
            &mut in_place_buffer,
            &last_modified_date_time.to_bytes(),
            &self.0.authorization_tag,
        )?;

        Ok((Mac(in_place_buffer, PhantomData), self.0.nonce))
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    #[cfg(all(feature = "aes-gcm", feature = "sha2"))]
    mod aes_gcm_sha2 {
        use std::marker::PhantomData;

        use crate::*;

        impl MockTestUtil for EncryptedMac<AES256GCM, SHA512> {
            fn mock() -> Self {
                Self(Self::mock_display().parse().unwrap(), PhantomData)
            }
        }

        impl MockDisplayTestUtil for EncryptedMac<AES256GCM, SHA512> {
            fn mock_display() -> String {
                "ENC[AES256_GCM,data:NGQmmmF7MMf3EiG3NY2iew5Ad3QrzoRD6lM4+Z7VbusLhu6yUksN3m410KWQNBYnGpowa3XgjSoajvn3RKmkV04CiU7dK3A0de+lXkX7Uvq2MzqAjI84gNdnIw9Ove4B18ioQHuL4h01E1eIXxhZcQ9qWIt91cNjyhcbEs2BWqQ=,iv:ufPWRTNV2fS3n/T/ptAhsre2S37rH5p8CgBAiK2c8r0=,tag:uHQApLnlF8NB/Gac0xnh+g==,type:str]".to_string()
            }
        }
    }
}
