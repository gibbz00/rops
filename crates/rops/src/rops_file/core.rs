use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::*;

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "F: FileFormat")]
#[impl_tools::autoimpl(PartialEq)]
pub struct RopsFile<S: RopsFileState, F: FileFormat>
where
    <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
{
    #[serde(flatten)]
    pub map: RopsFileFormatMap<S::MapState, F>,
    #[serde(rename = "sops")]
    pub metadata: RopsFileMetadata<S::MetadataState>,
}

#[derive(Debug, Error)]
pub enum RopsFileEncryptError {
    #[error("invalid decrypted map format: {0}")]
    FormatToIntenrnalMap(#[from] FormatToInternalMapError),
    #[error("unable to retrieve data key: {0}")]
    DataKeyRetrieval(#[from] RopsFileMetadataDataKeyRetrievalError),
    #[error("unable to encrypt map: {0}")]
    MapEncryption(anyhow::Error),
    #[error("unable to encrypt metadata: {0}")]
    MetadataEncryption(anyhow::Error),
}

#[derive(Debug, Error)]
pub enum RopsFileDecryptError {
    #[error("invalid encrypted map format; {0}")]
    FormatToIntenrnalMap(#[from] FormatToInternalMapError),
    #[error("unable to decrypt map value: {0}")]
    DecryptValue(#[from] DecryptRopsValueError),
    #[error("unable to decrypt file metadata")]
    Metadata(#[from] RopsFileMetadataDecryptError),
    #[error("invalid MAC, computed {0}, stored {0}")]
    MacMismatch(String, String),
}

impl<S: RopsFileState, F: FileFormat> RopsFile<S, F>
where
    <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
{
    pub fn new(map: impl ToExternalMap<S::MapState>, metadata: RopsFileMetadata<S::MetadataState>) -> Self {
        Self {
            map: map.to_external::<F>(),
            metadata,
        }
    }
}

impl<S: RopsFileState, F: FileFormat> Display for RopsFile<S, F>
where
    <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", F::serialize_to_string(self).expect("failed to serialize rops map"))
    }
}

#[derive(Debug, Error)]
pub enum RopsFileFromStrError {
    #[error("deserialize error")]
    Deserialize(anyhow::Error),
}

impl<S: RopsFileState, F: FileFormat> FromStr for RopsFile<S, F>
where
    <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
{
    type Err = RopsFileFromStrError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        F::deserialize_from_str(str).map_err(|error| RopsFileFromStrError::Deserialize(error.into()))
    }
}

impl<H: Hasher, F: FileFormat> RopsFile<DecryptedFile<H>, F> {
    pub fn encrypt<C: Cipher, Fo: FileFormat>(self) -> Result<RopsFile<EncryptedFile<C, H>, Fo>, RopsFileEncryptError> {
        let data_key = self.metadata.retrieve_data_key()?;
        let encrypted_map = self
            .map
            .to_internal()?
            .encrypt::<C>(&data_key, self.metadata.partial_encryption.as_ref());
        let encrypted_metadata = self.metadata.encrypt::<C>(&data_key);
        Self::file_from_parts_results(encrypted_map, encrypted_metadata)
    }

    pub fn encrypt_with_saved_parameters<C: Cipher, Fo: FileFormat>(
        self,
        saved_parameters: SavedParameters<C, H>,
    ) -> Result<RopsFile<EncryptedFile<C, H>, Fo>, RopsFileEncryptError> {
        #[rustfmt::skip]
        let SavedParameters { data_key, saved_map_nonces, saved_mac_nonce } = saved_parameters;

        let encrypted_map =
            self.map
                .to_internal()?
                .encrypt_with_saved_nonces(&data_key, self.metadata.partial_encryption.as_ref(), &saved_map_nonces);

        let encrypted_metadata = self.metadata.encrypt_with_saved_mac_nonce::<C>(&data_key, saved_mac_nonce);
        Self::file_from_parts_results(encrypted_map, encrypted_metadata)
    }

    fn file_from_parts_results<C: Cipher, Fo: FileFormat>(
        encrypted_map_result: Result<RopsMap<EncryptedMap<C>>, C::Error>,
        encrypted_metadata_result: Result<RopsFileMetadata<EncryptedMetadata<C, H>>, C::Error>,
    ) -> Result<RopsFile<EncryptedFile<C, H>, Fo>, RopsFileEncryptError> {
        let encrypted_map = encrypted_map_result.map_err(|error| RopsFileEncryptError::MetadataEncryption(error.into()))?;
        let encrypted_metadata = encrypted_metadata_result.map_err(|error| RopsFileEncryptError::MetadataEncryption(error.into()))?;
        Ok(RopsFile::new(encrypted_map, encrypted_metadata))
    }
}

impl<C: Cipher, F: FileFormat, H: Hasher> RopsFile<EncryptedFile<C, H>, F> {
    pub fn decrypt<Fo: FileFormat>(self) -> Result<RopsFile<DecryptedFile<H>, Fo>, RopsFileDecryptError> {
        let (decrypted_metadata, data_key) = self.metadata.decrypt()?;
        let decrypted_map = self
            .map
            .to_internal(decrypted_metadata.partial_encryption.as_ref())?
            .decrypt(&data_key)?;
        Self::validate_mac(&decrypted_map, &decrypted_metadata)?;
        Ok(RopsFile::new(decrypted_map, decrypted_metadata))
    }

    #[allow(clippy::type_complexity)]
    pub fn decrypt_and_save_parameters<Fo: FileFormat>(
        self,
    ) -> Result<(RopsFile<DecryptedFile<H>, Fo>, SavedParameters<C, H>), RopsFileDecryptError> {
        let (decrypted_metadata, data_key, saved_mac_nonce) = self.metadata.decrypt_and_save_mac_nonce()?;
        let (decrypted_map, saved_map_nonces) = self
            .map
            .to_internal(decrypted_metadata.partial_encryption.as_ref())?
            .decrypt_and_save_nonces(&data_key)?;

        Self::validate_mac(&decrypted_map, &decrypted_metadata)?;

        Ok((
            RopsFile::new(decrypted_map, decrypted_metadata),
            SavedParameters {
                data_key,
                saved_map_nonces,
                saved_mac_nonce,
            },
        ))
    }

    fn validate_mac(
        decrypted_map: &RopsMap<DecryptedMap>,
        decrypted_metadata: &RopsFileMetadata<DecryptedMetadata<H>>,
    ) -> Result<(), RopsFileDecryptError> {
        let computed_mac = Mac::<H>::compute(MacOnlyEncryptedConfig::new(decrypted_metadata), decrypted_map);
        let stored_mac = &decrypted_metadata.mac;

        match &computed_mac != stored_mac {
            true => Err(RopsFileDecryptError::MacMismatch(computed_mac.to_string(), stored_mac.to_string())),
            false => Ok(()),
        }
    }
}
