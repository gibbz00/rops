use serde::{de::DeserializeOwned, Serialize};
use serde_yaml::{Mapping as YamlMap, Value as YamlValue};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct YamlFileFormat;

impl FileFormat for YamlFileFormat {
    type Map = YamlMap;

    type SerializeError = serde_yaml::Error;
    type DeserializeError = serde_yaml::Error;

    fn serialize_to_string<T: Serialize>(t: &T) -> Result<String, Self::SerializeError> {
        serde_yaml::to_string(t)
    }

    fn deserialize_from_str<T: DeserializeOwned>(str: &str) -> Result<T, Self::DeserializeError> {
        serde_yaml::from_str(str)
    }
}

impl FileFormatKeyAdapter for YamlValue {
    fn validate(self) -> Result<String, FormatToInternalMapError> {
        match self {
            YamlValue::String(string) => Ok(string),
            other => Err(FormatToInternalMapError::NonStringKey(
                serde_yaml::to_string(&other).expect("yaml value not serializable"),
            )),
        }
    }

    fn from_internal(key: String) -> Self {
        YamlValue::String(key)
    }
}

impl FileFormatMapAdapter for YamlMap {
    type Key = YamlValue;
    type Value = YamlValue;

    fn with_capacity(capacity: usize) -> Self {
        YamlMap::with_capacity(capacity)
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) {
        self.insert(key, value);
    }

    fn decrypted_format_to_internal_value(yaml_value: Self::Value) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError> {
        Ok(match yaml_value {
            // SOPS simply throws away tags, so do we for now.
            // It can, however, deserialize manually added tags to encrypted documents,
            // so we could in theory keep the tags somewhere without breaking SOPS compatability.
            YamlValue::Tagged(tagged) => Self::decrypted_format_to_internal_value(tagged.value)?,
            YamlValue::Mapping(map) => RopsTree::Map(YamlMap::decrypted_format_to_internal(
                map,
                Self::decrypted_format_to_internal_value,
            )?),
            YamlValue::Bool(boolean) => RopsTree::Leaf(RopsValue::Boolean(boolean)),
            YamlValue::String(string) => RopsTree::Leaf(RopsValue::String(string)),
            YamlValue::Number(number) => RopsTree::Leaf(tree_traversal::resolve_number(number)?),
            YamlValue::Sequence(sequence) => RopsTree::Sequence(
                sequence
                    .into_iter()
                    .map(Self::decrypted_format_to_internal_value)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            YamlValue::Null => RopsTree::Null,
        })
    }

    fn decrypted_internal_to_format_value(rops_tree: RopsTree<DecryptedMap>) -> Self::Value {
        match rops_tree {
            RopsTree::Sequence(sequence) => {
                YamlValue::Sequence(sequence.into_iter().map(Self::decrypted_internal_to_format_value).collect())
            }
            RopsTree::Map(map) => YamlValue::Mapping(Self::decrypted_internal_to_format(map)),
            RopsTree::Null => YamlValue::Null,
            RopsTree::Leaf(decrypted_value) => tree_traversal::internal_to_yaml_value(decrypted_value),
        }
    }

    fn encrypted_fomat_to_internal_value<C: Cipher>(
        yaml_value: Self::Value,
        resolved_partial_encryption: ResolvedPartialEncrpytion,
    ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError> {
        Ok(match yaml_value {
            YamlValue::Tagged(tagged) => Self::encrypted_fomat_to_internal_value(tagged.value, resolved_partial_encryption)?,
            YamlValue::Mapping(map) => {
                RopsTree::Map(map.encrypted_format_to_internal(resolved_partial_encryption, Self::encrypted_fomat_to_internal_value)?)
            }
            YamlValue::String(string) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::String(string))),
                false => RopsTree::Leaf(RopsMapEncryptedLeaf::Encrypted(string.parse()?)),
            },
            YamlValue::Sequence(sequence) => RopsTree::Sequence(
                sequence
                    .into_iter()
                    .map(|value| Self::encrypted_fomat_to_internal_value(value, resolved_partial_encryption))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            YamlValue::Null => RopsTree::Null,
            YamlValue::Bool(bool) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::Boolean(bool))),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(bool.to_string())),
            },
            YamlValue::Number(number) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(tree_traversal::resolve_number(number)?)),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(number.to_string())),
            },
        })
    }

    fn encrypted_internal_to_format_value<C: Cipher>(internal_tree: RopsTree<EncryptedMap<C>>) -> Self::Value {
        match internal_tree {
            RopsTree::Sequence(sequence) => {
                YamlValue::Sequence(sequence.into_iter().map(Self::encrypted_internal_to_format_value).collect())
            }
            RopsTree::Map(map) => YamlValue::Mapping(Self::encrypted_internal_to_format_map(map)),
            RopsTree::Null => YamlValue::Null,
            RopsTree::Leaf(maybe_encrypted_value) => match maybe_encrypted_value {
                RopsMapEncryptedLeaf::Encrypted(encrypted_value) => YamlValue::String(encrypted_value.to_string()),
                RopsMapEncryptedLeaf::Escaped(escaped_value) => tree_traversal::internal_to_yaml_value(escaped_value),
            },
        }
    }
}

mod tree_traversal {
    use super::*;

    pub fn resolve_number(number: serde_yaml::Number) -> Result<RopsValue, FormatToInternalMapError> {
        Ok(match number.is_f64() {
            true => RopsValue::Float(number.as_f64().expect("number not a f64").into()),
            false => RopsValue::Integer(
                number
                    .as_i64()
                    .ok_or_else(|| FormatToInternalMapError::IntegerOutOfRange(number.as_u64().expect("number not an u64")))?,
            ),
        })
    }

    pub fn internal_to_yaml_value(value: RopsValue) -> YamlValue {
        match value {
            RopsValue::String(string) => YamlValue::String(string),
            RopsValue::Boolean(bool) => YamlValue::Bool(bool),
            RopsValue::Integer(integer) => YamlValue::Number(integer.into()),
            RopsValue::Float(rops_float) => YamlValue::Number(f64::from(rops_float).into()),
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock;

#[cfg(test)]
mod tests;
