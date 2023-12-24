use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

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

#[derive(Debug, thiserror::Error)]
pub enum RopsFileEncryptError {
    #[error("invalid decrypted map format: {0}")]
    FormatToIntenrnalMap(#[from] FormatToInternalMapError),
    #[error("unable to retrieve data key: {0}")]
    DataKeyRetrieval(#[from] RopsFileMetadataDataKeyRetrievalError),
    #[error("unable to encrypt map: {0}")]
    MapEncryption(String),
    #[error("unable to encrypt metadata: {0}")]
    MetadataEncryption(String),
}

#[derive(Debug, thiserror::Error)]
pub enum RopsFileDecryptError {
    #[error("invalid encrypted map format; {0}")]
    FormatToIntenrnalMap(#[from] FormatToInternalMapError),
    #[error("unable to decrypt map value: {0}")]
    DecryptValue(#[from] DecryptRopsValueError),
    #[error("unable to decrypt file metadata: {0}")]
    Metadata(#[from] RopsFileMetadataDecryptError),
    #[error("invalid MAC, computed {0}, stored {0}")]
    MacMismatch(String, String),
}

impl<S: RopsFileState, F: FileFormat> RopsFile<S, F>
where
    <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
{
    pub fn new(map: impl Into<RopsFileFormatMap<S::MapState, F>>, metadata: RopsFileMetadata<S::MetadataState>) -> Self {
        Self { map: map.into(), metadata }
    }
}

impl<H: Hasher, F: FileFormat> RopsFile<DecryptedFile<H>, F> {
    pub fn encrypt<C: Cipher, Fo: FileFormat>(self) -> Result<RopsFile<EncryptedFile<C, H>, Fo>, RopsFileEncryptError>
    where
        RopsFileFormatMap<DecryptedMap, F>: TryInto<RopsMap<DecryptedMap>, Error = FormatToInternalMapError>,
        RopsMap<EncryptedMap<C>>: Into<Fo::Map>,
    {
        let data_key = self.metadata.retrieve_data_key()?;

        let encrypted_map = self
            .map
            .try_into()?
            .encrypt::<C>(&data_key)
            .map_err(|error| RopsFileEncryptError::MapEncryption(error.to_string()))?;

        let encrypted_metadata = self
            .metadata
            .encrypt::<C>(&data_key)
            .map_err(|error| RopsFileEncryptError::MetadataEncryption(error.to_string()))?;

        Ok(RopsFile::new(encrypted_map, encrypted_metadata))
    }

    pub fn encrypt_with_saved_parameters<C: Cipher, Fo: FileFormat>(
        self,
        saved_parameters: SavedParameters<C, H>,
    ) -> Result<RopsFile<EncryptedFile<C, H>, Fo>, RopsFileEncryptError>
    where
        RopsFileFormatMap<DecryptedMap, F>: TryInto<RopsMap<DecryptedMap>, Error = FormatToInternalMapError>,
        RopsMap<EncryptedMap<C>>: Into<Fo::Map>,
    {
        #[rustfmt::skip]
        let SavedParameters { data_key, saved_map_nonces, saved_mac_nonce } = saved_parameters;

        let encrypted_map = self
            .map
            .try_into()?
            .encrypt_with_saved_nonces(&data_key, &saved_map_nonces)
            .map_err(|error| RopsFileEncryptError::MetadataEncryption(error.to_string()))?;

        let encrypted_metadata = self
            .metadata
            .encrypt_with_saved_mac_nonce::<C>(&data_key, saved_mac_nonce)
            .map_err(|error| RopsFileEncryptError::MetadataEncryption(error.to_string()))?;

        Ok(RopsFile::new(encrypted_map, encrypted_metadata))
    }
}

impl<C: Cipher, F: FileFormat, H: Hasher> RopsFile<EncryptedFile<C, H>, F> {
    pub fn decrypt<Fo: FileFormat>(self) -> Result<RopsFile<DecryptedFile<H>, Fo>, RopsFileDecryptError>
    where
        RopsFileFormatMap<EncryptedMap<C>, F>: TryInto<RopsMap<EncryptedMap<C>>, Error = FormatToInternalMapError>,
        RopsMap<DecryptedMap>: Into<Fo::Map>,
    {
        let (decrypted_metadata, data_key) = self.metadata.decrypt()?;
        let decrypted_map = self.map.try_into()?.decrypt(&data_key)?;

        Self::validate_mac(&decrypted_map, &decrypted_metadata.mac)?;

        Ok(RopsFile::new(decrypted_map, decrypted_metadata))
    }

    #[allow(clippy::type_complexity)]
    pub fn decrypt_and_save_parameters<Fo: FileFormat>(
        self,
    ) -> Result<(RopsFile<DecryptedFile<H>, Fo>, SavedParameters<C, H>), RopsFileDecryptError>
    where
        RopsFileFormatMap<EncryptedMap<C>, F>: TryInto<RopsMap<EncryptedMap<C>>, Error = FormatToInternalMapError>,
        RopsMap<DecryptedMap>: Into<Fo::Map>,
    {
        let (decrypted_metadata, data_key, saved_mac_nonce) = self.metadata.decrypt_and_save_mac_nonce()?;
        let (decrypted_map, saved_map_nonces) = self.map.try_into()?.decrypt_and_save_nonces(&data_key)?;

        Self::validate_mac(&decrypted_map, &decrypted_metadata.mac)?;

        Ok((
            RopsFile::new(decrypted_map, decrypted_metadata),
            SavedParameters {
                data_key,
                saved_map_nonces,
                saved_mac_nonce,
            },
        ))
    }

    fn validate_mac(decrypted_map: &RopsMap<DecryptedMap>, stored_mac: &Mac<H>) -> Result<(), RopsFileDecryptError> {
        // TODO: use metadata.from_encrypted_values_only once partial encryption is added
        let computed_mac = Mac::<H>::compute(false, decrypted_map);

        match &computed_mac != stored_mac {
            true => Err(RopsFileDecryptError::MacMismatch(computed_mac.to_string(), stored_mac.to_string())),
            false => Ok(()),
        }
    }
}
