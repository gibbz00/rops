use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_with::DisplayFromStr;

use crate::*;

#[serde_with::serde_as]
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize)]
#[impl_tools::autoimpl(Debug, PartialEq)]
pub struct RopsFileMetadata<S: RopsMetadataState>
where
    <S::Mac as FromStr>::Err: Display,
{
    #[serde(flatten)]
    pub intregation: IntegrationMetadata,
    #[serde(rename = "lastmodified")]
    pub last_modified: LastModifiedDateTime,
    #[serde_as(as = "DisplayFromStr")]
    pub mac: S::Mac,
    #[serde(flatten)]
    pub partial_encryption: Option<PartialEncryptionConfig>,
    pub mac_only_encrypted: Option<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum RopsFileMetadataDecryptError {
    #[error("unable to decrypt MAC: {0}")]
    Mac(anyhow::Error),
    #[error("unable to retrieve data key: {0}")]
    DataKeyRetrieval(#[from] RopsFileMetadataDataKeyRetrievalError),
}

#[derive(Debug, thiserror::Error)]
pub enum RopsFileMetadataDataKeyRetrievalError {
    #[error("integration error; {0}")]
    Integration(#[from] IntegrationError),
    #[error("no data key found in metadata, make sure at least one integration is used")]
    MissingDataKey,
}

impl<S: RopsMetadataState> RopsFileMetadata<S>
where
    <S::Mac as FromStr>::Err: Display,
{
    pub(crate) fn retrieve_data_key(&self) -> Result<DataKey, RopsFileMetadataDataKeyRetrievalError> {
        match self.intregation.decrypt_data_key()? {
            Some(data_key) => Ok(data_key),
            None => Err(RopsFileMetadataDataKeyRetrievalError::MissingDataKey),
        }
    }
}

impl<C: Cipher, H: Hasher> RopsFileMetadata<EncryptedMetadata<C, H>> {
    pub fn decrypt(self) -> Result<(RopsFileMetadata<DecryptedMetadata<H>>, DataKey), RopsFileMetadataDecryptError> {
        let data_key = self.retrieve_data_key()?;

        #[rustfmt::skip]
        let RopsFileMetadata { intregation, last_modified, mac, partial_encryption, mac_only_encrypted } = self;

        let decrypted_map = mac
            .decrypt(&data_key, &last_modified)
            .map_err(|error| RopsFileMetadataDecryptError::Mac(error.into()))?;

        let decrypted_metadata = RopsFileMetadata {
            intregation,
            last_modified,
            mac: decrypted_map,
            partial_encryption,
            mac_only_encrypted,
        };

        Ok((decrypted_metadata, data_key))
    }

    #[allow(clippy::type_complexity)]
    pub fn decrypt_and_save_mac_nonce(
        self,
    ) -> Result<(RopsFileMetadata<DecryptedMetadata<H>>, DataKey, SavedMacNonce<C, H>), RopsFileMetadataDecryptError> {
        let data_key = self.retrieve_data_key()?;

        #[rustfmt::skip]
        let RopsFileMetadata { intregation, last_modified, mac, partial_encryption, mac_only_encrypted } = self;

        let (decrypted_map, saved_mac_nonce) = mac
            .decrypt_and_save_nonce(&data_key, &last_modified)
            .map_err(|error| RopsFileMetadataDecryptError::Mac(error.into()))?;

        let decrypted_metadata = RopsFileMetadata {
            intregation,
            last_modified,
            mac: decrypted_map,
            partial_encryption,
            mac_only_encrypted,
        };

        Ok((decrypted_metadata, data_key, saved_mac_nonce))
    }
}

impl<H: Hasher> RopsFileMetadata<DecryptedMetadata<H>> {
    pub fn encrypt<C: Cipher>(self, data_key: &DataKey) -> Result<RopsFileMetadata<EncryptedMetadata<C, H>>, C::Error> {
        #[rustfmt::skip]
        let RopsFileMetadata { intregation, last_modified, mac, partial_encryption, mac_only_encrypted } = self;

        Ok(RopsFileMetadata {
            intregation,
            mac: mac.encrypt(data_key, &last_modified)?,
            last_modified,
            partial_encryption,
            mac_only_encrypted,
        })
    }

    pub fn encrypt_with_saved_mac_nonce<C: Cipher>(
        self,
        data_key: &DataKey,
        saved_mac_nonce: SavedMacNonce<C, H>,
    ) -> Result<RopsFileMetadata<EncryptedMetadata<C, H>>, C::Error> {
        #[rustfmt::skip]
        let RopsFileMetadata { intregation, last_modified, mac, partial_encryption, mac_only_encrypted } = self;

        Ok(RopsFileMetadata {
            intregation,
            mac: mac.encrypt_with_saved_nonce(data_key, &last_modified, saved_mac_nonce)?,
            last_modified,
            partial_encryption,
            mac_only_encrypted,
        })
    }

    /// Returns the removed integration medata unit , if any.
    // NOTE: Assumes sync of encrypted/decrypted state between map and metadata in `RopsFile`.
    // (We don't want to update the data key when the map is encrypted.)
    // WORKAROUND: Handling done here to avoid adding type state parameters to IntegrationMetadata
    // E.g IntegrationMetadata<DecryptedIntegrationMetadata>::remove_integration_key()
    pub fn remove_integration_key<I: Integration>(&mut self, key_id: &I::KeyId) -> IntegrationResult<Option<IntegrationMetadataUnit<I>>> {
        let integration_keys = I::select_metadata_units(&mut self.intregation);

        let Some(removed_key) = integration_keys.remove(key_id) else {
            return Ok(None);
        };

        let new_data_key = DataKey::new();

        #[cfg(feature = "age")]
        update_data_key::<AgeIntegration>(&mut self.intregation, &new_data_key)?;

        #[cfg(feature = "aws-kms")]
        update_data_key::<AwsKmsIntegration>(&mut self.intregation, &new_data_key)?;

        return Ok(Some(removed_key));

        fn update_data_key<I: Integration>(
            integration_metadata: &mut IntegrationMetadata,
            new_data_key: &DataKey,
        ) -> IntegrationResult<()> {
            I::select_metadata_units(integration_metadata).values_mut().try_for_each(|unit| {
                I::encrypt_data_key(unit.config.key_id(), new_data_key)
                    .map(|encrypted_data_key| unit.encrypted_data_key = encrypted_data_key)
            })
        }
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
                intregation: IntegrationMetadata::mock(),
                last_modified: MockTestUtil::mock(),
                mac: MockTestUtil::mock(),
                partial_encryption: Some(MockTestUtil::mock()),
                mac_only_encrypted: None,
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
    }

    #[cfg(all(feature = "age", feature = "aws-kms", feature = "sha2"))]
    mod key_removal {
        use crate::*;

        #[test]
        fn removes_key() {
            let mut metadata = RopsFileMetadata::<DecryptedMetadata<SHA512>>::mock();

            let new_age_key_id = "age18e57g4yp3anhs0xpssgmy7x0u23tryqzpew0t3x2h4yzqx029yfqu7xfgg"
                .parse::<<AgeIntegration as Integration>::KeyId>()
                .unwrap();

            let new_age_identity = "AGE-SECRET-KEY-1RQHTSUKPA93KMCUJ0LDZ5DWW3VMVJRHAWGK5ZM6835FU9KEYQ90SVQ46JQ";

            AwsKmsIntegration::set_mock_private_key_env_var();
            std::env::set_var(AgeIntegration::private_key_env_var_name(), new_age_identity);

            metadata
                .intregation
                .add_keys::<AgeIntegration>(Some(new_age_key_id.clone()), &DataKey::mock())
                .unwrap();

            assert_eq!(metadata.intregation.age.len(), 2);

            metadata.remove_integration_key::<AgeIntegration>(&MockTestUtil::mock()).unwrap();

            assert_eq!(metadata.intregation.age.len(), 1);

            assert_ne!(
                DataKey::mock(),
                AgeIntegration::decrypt_data_key(&new_age_key_id, &metadata.intregation.age.first().unwrap().1.encrypted_data_key)
                    .unwrap()
                    .unwrap()
            )
        }
    }
}
