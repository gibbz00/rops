use std::fmt::Debug;

use indexmap::IndexMap;
use serde::{de::DeserializeOwned, Serialize};

use crate::*;

pub trait FileFormatKeyAdapter {
    /// Only strings are allowed to be keys.
    fn validate(self) -> Result<String, FormatToInternalMapError>;

    fn from_internal(key: String) -> Self;
}

pub trait FileFormatValueAdapter {
    fn decrypted_to_internal(self) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError>;

    fn decrypted_from_internal(rops_tree: RopsTree<DecryptedMap>) -> Self;

    fn encrypted_to_internal<C: Cipher>(
        self,
        resolved_partial_encryption: ResolvedPartialEncrpytion,
    ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError>;

    fn encrypted_from_internal<C: Cipher>(internal_tree: RopsTree<EncryptedMap<C>>) -> Self;
}

pub trait FileFormatMapAdapter: Sized + Serialize + DeserializeOwned + PartialEq + Debug
where
    Self: IntoIterator<Item = (Self::Key, Self::Value)>,
{
    type Key: FileFormatKeyAdapter;
    type Value: FileFormatValueAdapter;

    fn with_capacity(capacity: usize) -> Self;

    fn insert(&mut self, key: Self::Key, value: Self::Value);

    fn decrypted_to_internal<F, S: RopsMapState>(self, recursive_value_fn: F) -> Result<RopsMap<S>, FormatToInternalMapError>
    where
        F: Fn(Self::Value) -> Result<RopsTree<S>, FormatToInternalMapError>,
    {
        let mut tree_map = IndexMap::default();

        for (format_key, format_value) in self {
            let key_string = format_key.validate()?;
            tree_map.insert(key_string, recursive_value_fn(format_value)?);
        }

        Ok(tree_map.into())
    }

    fn decrypted_from_internal(rops_map: RopsMap<DecryptedMap>) -> Self {
        let mut format_map = Self::with_capacity(rops_map.len());

        for (key, value) in rops_map.0 {
            format_map.insert(Self::Key::from_internal(key), Self::Value::decrypted_from_internal(value));
        }

        format_map
    }

    fn encrypted_to_internal<F, C: Cipher>(
        self,
        resolved_partial_encryption: ResolvedPartialEncrpytion,
        recursive_value_fn: F,
    ) -> Result<RopsMap<EncryptedMap<C>>, FormatToInternalMapError>
    where
        F: Fn(Self::Value, ResolvedPartialEncrpytion) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError>,
    {
        let mut tree_map = IndexMap::default();

        for (yaml_key, yaml_value) in self {
            let key_string = yaml_key.validate()?;
            let mut resolved_partial_encryption = resolved_partial_encryption;

            if let ResolvedPartialEncrpytion::No(partial_encryption_config) = resolved_partial_encryption {
                resolved_partial_encryption = partial_encryption_config.resolve(&key_string);
            }

            tree_map.insert(key_string, recursive_value_fn(yaml_value, resolved_partial_encryption)?);
        }

        Ok(tree_map.into())
    }

    fn encrypted_from_internal<C: Cipher>(internal_map: RopsMap<EncryptedMap<C>>) -> Self {
        let mut format_map = Self::with_capacity(internal_map.len());

        for (key, tree) in internal_map.0 {
            format_map.insert(Self::Key::from_internal(key), Self::Value::encrypted_from_internal(tree));
        }

        format_map
    }
}
