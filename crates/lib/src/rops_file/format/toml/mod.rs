#[cfg(feature = "test-utils")]
mod mock;

#[cfg(test)]
mod tests;

use serde::{de::DeserializeOwned, Serialize};
use toml::{map::Map as TomlMap, Value as TomlValue};

use crate::*;

/*
    Unresolved questions:
    - How should `TomlValue::Datetime`s be handled?
    - How should `RopsValue::Null` to `TomlValue` be handled?
*/
#[derive(Debug, PartialEq)]
pub struct TomlFileFormat;

impl FileFormat for TomlFileFormat {
    type Map = TomlMap<String, TomlValue>;

    type SerializeError = toml::ser::Error;
    type DeserializeError = toml::de::Error;

    fn serialize_to_string<T: Serialize>(t: &T) -> Result<String, Self::SerializeError> {
        toml::to_string_pretty(t)
    }

    fn deserialize_from_str<T: DeserializeOwned>(str: &str) -> Result<T, Self::DeserializeError> {
        toml::from_str(str)
    }
}

impl FileFormatMapAdapter for TomlMap<String, TomlValue> {
    type Key = String;
    type Value = TomlValue;

    fn with_capacity(capacity: usize) -> Self {
        TomlMap::with_capacity(capacity)
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) {
        self.insert(key, value);
    }
}

impl FileFormatValueAdapter for TomlValue {
    fn decrypted_to_internal(self) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError> {
        Ok(match self {
            TomlValue::Table(map) => RopsTree::Map(TomlMap::decrypted_to_internal(map)?),
            TomlValue::Boolean(boolean) => RopsTree::Leaf(RopsValue::Boolean(boolean)),
            // TEMP:
            TomlValue::String(string) if &string == "null" => RopsTree::Null,
            TomlValue::String(string) => RopsTree::Leaf(RopsValue::String(string)),
            TomlValue::Integer(integer) => RopsTree::Leaf(RopsValue::Integer(integer)),
            TomlValue::Float(float) => RopsTree::Leaf(RopsValue::Float(float.into())),
            TomlValue::Array(sequence) => RopsTree::Sequence(
                sequence
                    .into_iter()
                    .map(Self::decrypted_to_internal)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            TomlValue::Datetime(datetime) => RopsTree::Leaf(RopsValue::String(datetime.to_string())),
        })
    }

    fn decrypted_from_internal(rops_tree: RopsTree<DecryptedMap>) -> Self {
        match rops_tree {
            RopsTree::Sequence(sequence) => TomlValue::Array(sequence.into_iter().map(Self::decrypted_from_internal).collect()),
            RopsTree::Map(map) => TomlValue::Table(TomlMap::decrypted_from_internal(map)),
            // TEMP:
            RopsTree::Null => TomlValue::String("null".to_string()),
            RopsTree::Leaf(decrypted_value) => helpers::from_internal_value(decrypted_value),
        }
    }

    fn encrypted_to_internal<C: Cipher>(
        self,
        resolved_partial_encryption: ResolvedPartialEncrpytion,
    ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError> {
        Ok(match self {
            TomlValue::Table(map) => RopsTree::Map(map.encrypted_to_internal(resolved_partial_encryption, Self::encrypted_to_internal)?),
            TomlValue::Array(sequence) => RopsTree::Sequence(
                sequence
                    .into_iter()
                    .map(|value| value.encrypted_to_internal(resolved_partial_encryption))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            // TEMP:
            TomlValue::String(string) if &string == "null" => RopsTree::Null,
            TomlValue::String(string) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::String(string))),
                false => RopsTree::Leaf(RopsMapEncryptedLeaf::Encrypted(string.parse()?)),
            },
            TomlValue::Boolean(bool) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::Boolean(bool))),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(bool.to_string())),
            },
            TomlValue::Integer(integer) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::Integer(integer))),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(integer.to_string())),
            },
            TomlValue::Float(float) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::Float(float.into()))),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(float.to_string())),
            },
            TomlValue::Datetime(datetime) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::String(datetime.to_string()))),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(datetime.to_string())),
            },
        })
    }

    fn encrypted_from_internal<C: Cipher>(internal_tree: RopsTree<EncryptedMap<C>>) -> Self {
        match internal_tree {
            RopsTree::Sequence(sequence) => TomlValue::Array(sequence.into_iter().map(Self::encrypted_from_internal).collect()),
            RopsTree::Map(map) => TomlValue::Table(TomlMap::encrypted_from_internal(map)),
            // TEMP:
            RopsTree::Null => TomlValue::String("null".to_string()),
            RopsTree::Leaf(maybe_encrypted_value) => match maybe_encrypted_value {
                RopsMapEncryptedLeaf::Encrypted(encrypted_value) => TomlValue::String(encrypted_value.to_string()),
                RopsMapEncryptedLeaf::Escaped(escaped_value) => helpers::from_internal_value(escaped_value),
            },
        }
    }
}

mod helpers {
    use super::*;

    pub fn from_internal_value(value: RopsValue) -> TomlValue {
        match value {
            RopsValue::String(string) => TomlValue::String(string),
            RopsValue::Boolean(bool) => TomlValue::Boolean(bool),
            RopsValue::Integer(integer) => TomlValue::Integer(integer),
            RopsValue::Float(rops_float) => TomlValue::Float(rops_float.into()),
        }
    }
}
