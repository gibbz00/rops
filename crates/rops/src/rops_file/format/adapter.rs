use std::fmt::Debug;

use indexmap::IndexMap;
use serde::{de::DeserializeOwned, Serialize};

use crate::*;

// TODO: pub(crate)
pub trait FileFormatMapAdapter: Sized + Serialize + DeserializeOwned + PartialEq + Debug
where
    Self: IntoIterator<Item = (Self::Key, Self::Value)>,
{
    type Key;
    type Value;

    /// Only strings are allowed to be keys (SOPS requirement).
    fn validate_key(key: Self::Key) -> Result<String, FormatToInternalMapError>;

    fn new_string_key(key_string: String) -> Self::Key;

    fn with_capacity(capacity: usize) -> Self;

    fn insert(&mut self, key: Self::Key, value: Self::Value);

    fn decrypted_format_to_internal<F, S: RopsMapState>(self, recursive_value_fn: F) -> Result<RopsMap<S>, FormatToInternalMapError>
    where
        F: Fn(Self::Value) -> Result<RopsTree<S>, FormatToInternalMapError>,
    {
        let mut tree_map = IndexMap::default();

        for (format_key, format_value) in self {
            let key_string = Self::validate_key(format_key)?;
            tree_map.insert(key_string, recursive_value_fn(format_value)?);
        }

        Ok(tree_map.into())
    }

    fn decrypted_format_to_internal_value(format_value: Self::Value) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError>;

    fn decrypted_internal_to_format(rops_map: RopsMap<DecryptedMap>) -> Self {
        let mut format_map = Self::with_capacity(rops_map.len());

        for (key, value) in rops_map.0 {
            format_map.insert(Self::new_string_key(key), Self::decrypted_internal_to_format_value(value));
        }

        format_map
    }

    fn decrypted_internal_to_format_value(rops_tree: RopsTree<DecryptedMap>) -> Self::Value;

    fn encrypted_format_to_internal<F, C: Cipher>(
        self,
        resolved_partial_encryption: ResolvedPartialEncrpytion,
        recursive_value_fn: F,
    ) -> Result<RopsMap<EncryptedMap<C>>, FormatToInternalMapError>
    where
        F: Fn(Self::Value, ResolvedPartialEncrpytion) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError>,
    {
        let mut tree_map = IndexMap::default();

        for (yaml_key, yaml_value) in self {
            let key_string = Self::validate_key(yaml_key)?;
            let mut resolved_partial_encryption = resolved_partial_encryption;

            if let ResolvedPartialEncrpytion::No(partial_encryption_config) = resolved_partial_encryption {
                resolved_partial_encryption = partial_encryption_config.resolve(&key_string);
            }

            tree_map.insert(key_string, recursive_value_fn(yaml_value, resolved_partial_encryption)?);
        }

        Ok(tree_map.into())
    }

    fn encrypted_fomat_to_internal_value<C: Cipher>(
        format_value: Self::Value,
        resolved_partial_encryption: ResolvedPartialEncrpytion,
    ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError>;

    fn encrypted_internal_to_format_map<C: Cipher>(internal_map: RopsMap<EncryptedMap<C>>) -> Self {
        let mut format_map = Self::with_capacity(internal_map.len());

        for (key, tree) in internal_map.0 {
            format_map.insert(Self::new_string_key(key), Self::encrypted_internal_to_format_value(tree));
        }

        format_map
    }

    fn encrypted_internal_to_format_value<C: Cipher>(internal_tree: RopsTree<EncryptedMap<C>>) -> Self::Value;
}
