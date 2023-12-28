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
        match self.intregation.find_data_key()? {
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
}
