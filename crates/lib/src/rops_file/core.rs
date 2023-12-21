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

impl<C: Cipher, F: FileFormat, H: Hasher> RopsFile<EncryptedFile<C, H>, F> {
    pub fn decrypt<Fo: FileFormat>(self) -> Result<RopsFile<DecryptedFile<H>, Fo>, RopsFileDecryptError>
    where
        RopsFileFormatMap<EncryptedMap<C>, F>: TryInto<RopsMap<EncryptedMap<C>>, Error = FormatToInternalMapError>,
        RopsMap<DecryptedMap>: Into<RopsFileFormatMap<DecryptedMap, Fo>>,
    {
        let (decrypted_metadata, data_key) = self.metadata.decrypt()?;
        let decrypted_map = self.map.try_into()?.decrypt(&data_key)?;

        // TODO: use metadata.from_encrypted_values_only once partial encryption is added
        let computed_mac = Mac::<H>::compute(false, &decrypted_map);
        let stored_mac = &decrypted_metadata.mac;
        if &computed_mac != stored_mac {
            return Err(RopsFileDecryptError::MacMismatch(computed_mac.to_string(), stored_mac.to_string()));
        }

        Ok(RopsFile {
            map: decrypted_map.into(),
            metadata: decrypted_metadata,
        })
    }

    pub fn decrypt_and_save_nonces() {
        todo!()
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<S: RopsFileState, F: FileFormat> MockTestUtil for RopsFile<S, F>
    where
        RopsFileFormatMap<S::MapState, F>: MockTestUtil,
        RopsFileMetadata<S::MetadataState>: MockTestUtil,
        <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
    {
        fn mock() -> Self {
            Self {
                map: MockTestUtil::mock(),
                metadata: MockTestUtil::mock(),
            }
        }
    }
}
