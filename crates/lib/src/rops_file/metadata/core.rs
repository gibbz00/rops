use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;

use crate::*;

#[serde_with::serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[impl_tools::autoimpl(PartialEq)]
pub struct RopsFileMetadata<S: RopsMetadataState>
where
    <S::Mac as FromStr>::Err: Display,
{
    #[cfg(feature = "age")]
    pub age: Vec<RopsFileAgeMetadata>,
    #[serde(rename = "lastmodified")]
    pub last_modified: LastModifiedDateTime,
    #[serde_as(as = "DisplayFromStr")]
    pub mac: S::Mac,
}

#[derive(Debug, thiserror::Error)]
pub enum RopsFileMetadataDecryptError {
    #[error("unable to decrypt MAC: {0}")]
    Mac(String),
    #[error("integration returned error during data key retrieval; {0}")]
    Integration(#[from] IntegrationError),
    #[error("no data key found in metadata, make sure at least one integration is used")]
    MissingDataKey,
}

impl<C: Cipher, H: Hasher> RopsFileMetadata<EncryptedMetadata<C, H>> {
    pub fn decrypt(self) -> Result<(RopsFileMetadata<DecryptedMetadata<H>>, DataKey), RopsFileMetadataDecryptError> {
        let data_key = self.retrieve_data_key()?;

        let decrypted_map = self
            .mac
            .decrypt(&data_key, &self.last_modified)
            .map_err(|error| RopsFileMetadataDecryptError::Mac(error.to_string()))?;

        let decrypted_metadata = RopsFileMetadata {
            #[cfg(feature = "age")]
            age: self.age,

            last_modified: self.last_modified,
            mac: decrypted_map,
        };

        Ok((decrypted_metadata, data_key))
    }

    #[allow(clippy::type_complexity)]
    pub fn decrypt_and_save_mac_nonce(
        self,
    ) -> Result<(RopsFileMetadata<DecryptedMetadata<H>>, DataKey, SavedMacNonce<C, H>), RopsFileMetadataDecryptError> {
        let data_key = self.retrieve_data_key()?;

        let (decrypted_map, saved_mac_nonce) = self
            .mac
            .decrypt_and_save_nonce(&data_key, &self.last_modified)
            .map_err(|error| RopsFileMetadataDecryptError::Mac(error.to_string()))?;

        let decrypted_metadata = RopsFileMetadata {
            #[cfg(feature = "age")]
            age: self.age,

            last_modified: self.last_modified,
            mac: decrypted_map,
        };

        Ok((decrypted_metadata, data_key, saved_mac_nonce))
    }

    fn retrieve_data_key(&self) -> Result<DataKey, RopsFileMetadataDecryptError> {
        match self.find_data_key()? {
            Some(data_key) => Ok(data_key),
            None => Err(RopsFileMetadataDecryptError::MissingDataKey),
        }
    }

    fn find_data_key(&self) -> IntegrationResult<Option<DataKey>> {
        // In order of what is assumed to be quickest:

        #[cfg(feature = "age")]
        if let Some(data_key) = self.data_key_from_age()? {
            return Ok(Some(data_key));
        }

        Ok(None)
    }

    #[cfg(feature = "age")]
    fn data_key_from_age(&self) -> IntegrationResult<Option<DataKey>> {
        let private_keys = AgeIntegration::retrieve_private_keys()?;

        for age_metadata in &self.age {
            for private_key in &private_keys {
                if private_key.to_public() == age_metadata.public_key {
                    return AgeIntegration::decrypt_data_key(private_key, &age_metadata.encrypted_data_key).map(Some);
                }
            }
        }

        Ok(None)
    }
}

impl<H: Hasher> RopsFileMetadata<DecryptedMetadata<H>> {
    pub fn encrypt<C: Cipher>(self, data_key: &DataKey) -> Result<RopsFileMetadata<EncryptedMetadata<C, H>>, C::Error> {
        Ok(RopsFileMetadata {
            #[cfg(feature = "age")]
            age: self.age,

            mac: self.mac.encrypt(data_key, &self.last_modified)?,
            last_modified: self.last_modified,
        })
    }

    pub fn encrypt_with_saved_mac_nonce<C: Cipher>(
        self,
        data_key: &DataKey,
        saved_mac_nonce: SavedMacNonce<C, H>,
    ) -> Result<RopsFileMetadata<EncryptedMetadata<C, H>>, C::Error> {
        Ok(RopsFileMetadata {
            #[cfg(feature = "age")]
            age: self.age,

            mac: self.mac.encrypt_with_saved_nonce(data_key, &self.last_modified, saved_mac_nonce)?,
            last_modified: self.last_modified,
        })
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<S: RopsMetadataState> MockTestUtil for RopsFileMetadata<S>
    where
        S::Mac: MockTestUtil,
        <S::Mac as FromStr>::Err: Display,
    {
        fn mock() -> Self {
            Self {
                #[cfg(feature = "age")]
                age: vec![MockTestUtil::mock()],

                last_modified: MockTestUtil::mock(),
                mac: MockTestUtil::mock(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "aes-gcm", feature = "sha2"))]
    mod aes_gcm_sha2 {
        use crate::*;

        #[test]
        fn encrypts_metadata() {
            assert_eq!(
                RopsFileMetadata::mock(),
                RopsFileMetadata::<DecryptedMetadata<SHA512>>::mock()
                    .encrypt::<AES256GCM>(&DataKey::mock())
                    .unwrap()
                    .decrypt()
                    .unwrap()
                    .0
            )
        }

        #[test]
        fn encrypts_with_saved_mac_nonce() {
            assert_eq!(
                RopsFileMetadata::mock(),
                RopsFileMetadata::mock()
                    .encrypt_with_saved_mac_nonce(&DataKey::mock(), SavedMacNonce::mock())
                    .unwrap()
            )
        }

        #[test]
        fn decrypts_metadata() {
            assert_eq!(
                RopsFileMetadata::mock(),
                RopsFileMetadata::<EncryptedMetadata<AES256GCM, SHA512>>::mock()
                    .decrypt()
                    .unwrap()
                    .0
            )
        }

        #[test]
        fn decrypts_and_saves_mac_nonce() {
            let (decrypted_metadata, _, saved_mac_nonce) = RopsFileMetadata::<EncryptedMetadata<AES256GCM, SHA512>>::mock()
                .decrypt_and_save_mac_nonce()
                .unwrap();

            assert_eq!(RopsFileMetadata::mock(), decrypted_metadata);
            assert_eq!(SavedMacNonce::mock(), saved_mac_nonce);
        }

        #[cfg(feature = "age")]
        mod age {
            use super::*;

            #[test]
            fn gets_data_key_from_age() {
                AgeIntegration::set_mock_private_key_env_var();
                assert_eq!(
                    DataKey::mock(),
                    RopsFileMetadata::<EncryptedMetadata<AES256GCM, SHA512>>::mock()
                        .data_key_from_age()
                        .unwrap()
                        .unwrap()
                )
            }
        }
    }
}
