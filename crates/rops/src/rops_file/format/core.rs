use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

use crate::*;

pub trait FileFormat: Sized {
    type Map: Serialize + DeserializeOwned + PartialEq + Debug;

    type SerializeError: std::error::Error + Send + Sync + 'static;
    type DeserializeError: std::error::Error + Send + Sync + 'static;

    fn serialize_to_string<T: Serialize>(t: &T) -> Result<String, Self::SerializeError>;

    fn deserialize_from_str<T: DeserializeOwned>(str: &str) -> Result<T, Self::DeserializeError>;

    fn encrypted_to_internal<C: Cipher>(
        format_map: RopsFileFormatMap<EncryptedMap<C>, Self>,
        partial_encryption: Option<&PartialEncryptionConfig>,
    ) -> Result<RopsMap<EncryptedMap<C>>, FormatToInternalMapError>;

    fn encrypted_from_internal<C: Cipher>(rops_map: RopsMap<EncryptedMap<C>>) -> Self::Map;

    fn decrypted_to_internal(format_map: RopsFileFormatMap<DecryptedMap, Self>) -> Result<RopsMap<DecryptedMap>, FormatToInternalMapError>;

    fn decrypted_from_internal(rops_map: RopsMap<DecryptedMap>) -> Self::Map;
}
