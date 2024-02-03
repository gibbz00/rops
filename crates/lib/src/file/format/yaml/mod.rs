#[cfg(feature = "test-utils")]
mod mock;

#[cfg(test)]
mod tests;

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

impl FileFormatMapAdapter for YamlMap {
    type Key = YamlValue;
    type Value = YamlValue;

    fn with_capacity(capacity: usize) -> Self {
        YamlMap::with_capacity(capacity)
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) {
        self.insert(key, value);
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

impl FileFormatValueAdapter for YamlValue {
    fn decrypted_to_internal(self) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError> {
        Ok(match self {
            // SOPS simply throws away tags, so do we for now.
            // It can, however, deserialize manually added tags to encrypted documents,
            // so we could in theory keep the tags somewhere without breaking SOPS compatability.
            YamlValue::Tagged(tagged) => tagged.value.decrypted_to_internal()?,
            YamlValue::Mapping(map) => RopsTree::Map(YamlMap::decrypted_to_internal(map)?),
            YamlValue::Bool(boolean) => RopsTree::Leaf(RopsValue::Boolean(boolean)),
            YamlValue::String(string) => RopsTree::Leaf(RopsValue::String(string)),
            YamlValue::Number(number) => RopsTree::Leaf(helpers::to_internal_number(number)?),
            YamlValue::Sequence(sequence) => RopsTree::Sequence(
                sequence
                    .into_iter()
                    .map(Self::decrypted_to_internal)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            YamlValue::Null => RopsTree::Null,
        })
    }

    fn decrypted_from_internal(rops_tree: RopsTree<DecryptedMap>) -> Self {
        match rops_tree {
            RopsTree::Sequence(sequence) => YamlValue::Sequence(sequence.into_iter().map(Self::decrypted_from_internal).collect()),
            RopsTree::Map(map) => YamlValue::Mapping(YamlMap::decrypted_from_internal(map)),
            RopsTree::Null => YamlValue::Null,
            RopsTree::Leaf(decrypted_value) => helpers::from_internal_value(decrypted_value),
        }
    }

    fn encrypted_to_internal<C: Cipher>(
        self,
        resolved_partial_encryption: ResolvedPartialEncrpytion,
    ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError> {
        Ok(match self {
            YamlValue::Tagged(tagged) => tagged.value.encrypted_to_internal(resolved_partial_encryption)?,
            YamlValue::Mapping(map) => RopsTree::Map(map.encrypted_to_internal(resolved_partial_encryption, Self::encrypted_to_internal)?),
            YamlValue::String(string) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::String(string))),
                false => RopsTree::Leaf(RopsMapEncryptedLeaf::Encrypted(string.parse()?)),
            },
            YamlValue::Sequence(sequence) => RopsTree::Sequence(
                sequence
                    .into_iter()
                    .map(|value| value.encrypted_to_internal(resolved_partial_encryption))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            YamlValue::Null => RopsTree::Null,
            YamlValue::Bool(bool) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::Boolean(bool))),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(bool.to_string())),
            },
            YamlValue::Number(number) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(helpers::to_internal_number(number)?)),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(number.to_string())),
            },
        })
    }

    fn encrypted_from_internal<C: Cipher>(internal_tree: RopsTree<EncryptedMap<C>>) -> Self {
        match internal_tree {
            RopsTree::Sequence(sequence) => YamlValue::Sequence(sequence.into_iter().map(Self::encrypted_from_internal).collect()),
            RopsTree::Map(map) => YamlValue::Mapping(YamlMap::encrypted_from_internal(map)),
            RopsTree::Null => YamlValue::Null,
            RopsTree::Leaf(maybe_encrypted_value) => match maybe_encrypted_value {
                RopsMapEncryptedLeaf::Encrypted(encrypted_value) => YamlValue::String(encrypted_value.to_string()),
                RopsMapEncryptedLeaf::Escaped(escaped_value) => helpers::from_internal_value(escaped_value),
            },
        }
    }
}

mod helpers {
    use super::*;

    pub fn to_internal_number(number: serde_yaml::Number) -> Result<RopsValue, FormatToInternalMapError> {
        Ok(match number.is_f64() {
            true => RopsValue::Float(number.as_f64().expect("number not a f64").into()),
            false => RopsValue::Integer(
                number
                    .as_i64()
                    .ok_or_else(|| FormatToInternalMapError::IntegerOutOfRange(number.as_u64().expect("number not an u64")))?,
            ),
        })
    }

    pub fn from_internal_value(value: RopsValue) -> YamlValue {
        match value {
            RopsValue::String(string) => YamlValue::String(string),
            RopsValue::Boolean(bool) => YamlValue::Bool(bool),
            RopsValue::Integer(integer) => YamlValue::Number(integer.into()),
            RopsValue::Float(rops_float) => YamlValue::Number(f64::from(rops_float).into()),
        }
    }
}
