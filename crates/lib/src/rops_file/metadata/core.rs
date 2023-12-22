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
        let Some(data_key) = self.retrieve_data_key()? else {
            return Err(RopsFileMetadataDecryptError::MissingDataKey);
        };

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

    fn retrieve_data_key(&self) -> IntegrationResult<Option<DataKey>> {
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
        fn decrypts_metadata() {
            assert_eq!(
                RopsFileMetadata::mock(),
                RopsFileMetadata::<EncryptedMetadata<AES256GCM, SHA512>>::mock()
                    .decrypt()
                    .unwrap()
                    .0
            )
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
