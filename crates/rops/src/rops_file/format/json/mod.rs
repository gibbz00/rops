#[cfg(feature = "test-utils")]
mod mock;

#[cfg(test)]
mod tests;

use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct JsonFileFormat;

impl FileFormat for JsonFileFormat {
    type Map = JsonMap<String, JsonValue>;

    type SerializeError = serde_json::Error;
    type DeserializeError = serde_json::Error;

    fn serialize_to_string<T: Serialize>(t: &T) -> Result<String, Self::SerializeError> {
        serde_json::to_string(t)
    }

    fn deserialize_from_str<T: DeserializeOwned>(str: &str) -> Result<T, Self::DeserializeError> {
        serde_json::from_str(str)
    }
}

impl FileFormatMapAdapter for JsonMap<String, JsonValue> {
    type Key = String;
    type Value = JsonValue;

    fn with_capacity(capacity: usize) -> Self {
        JsonMap::with_capacity(capacity)
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) {
        self.insert(key, value);
    }
}

impl FileFormatValueAdapter for JsonValue {
    fn decrypted_to_internal(self) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError> {
        Ok(match self {
            JsonValue::Object(map) => RopsTree::Map(JsonMap::decrypted_to_internal(map, Self::decrypted_to_internal)?),
            JsonValue::Bool(boolean) => RopsTree::Leaf(RopsValue::Boolean(boolean)),
            JsonValue::String(string) => RopsTree::Leaf(RopsValue::String(string)),
            JsonValue::Number(number) => RopsTree::Leaf(helpers::to_internal_number(number)?),
            JsonValue::Array(sequence) => RopsTree::Sequence(
                sequence
                    .into_iter()
                    .map(Self::decrypted_to_internal)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            JsonValue::Null => RopsTree::Null,
        })
    }

    fn decrypted_from_internal(rops_tree: RopsTree<DecryptedMap>) -> Self {
        match rops_tree {
            RopsTree::Sequence(sequence) => JsonValue::Array(sequence.into_iter().map(Self::decrypted_from_internal).collect()),
            RopsTree::Map(map) => JsonValue::Object(JsonMap::decrypted_from_internal(map)),
            RopsTree::Null => JsonValue::Null,
            RopsTree::Leaf(decrypted_value) => helpers::from_internal_value(decrypted_value),
        }
    }

    fn encrypted_to_internal<C: Cipher>(
        self,
        resolved_partial_encryption: ResolvedPartialEncrpytion,
    ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError> {
        Ok(match self {
            JsonValue::Object(map) => RopsTree::Map(map.encrypted_to_internal(resolved_partial_encryption, Self::encrypted_to_internal)?),
            JsonValue::String(string) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::String(string))),
                false => RopsTree::Leaf(RopsMapEncryptedLeaf::Encrypted(string.parse()?)),
            },
            JsonValue::Array(sequence) => RopsTree::Sequence(
                sequence
                    .into_iter()
                    .map(|value| value.encrypted_to_internal(resolved_partial_encryption))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            JsonValue::Null => RopsTree::Null,
            JsonValue::Bool(bool) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::Boolean(bool))),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(bool.to_string())),
            },
            JsonValue::Number(number) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(helpers::to_internal_number(number)?)),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(number.to_string())),
            },
        })
    }

    fn encrypted_from_internal<C: Cipher>(internal_tree: RopsTree<EncryptedMap<C>>) -> Self {
        match internal_tree {
            RopsTree::Sequence(sequence) => JsonValue::Array(sequence.into_iter().map(Self::encrypted_from_internal).collect()),
            RopsTree::Map(map) => JsonValue::Object(JsonMap::encrypted_from_internal(map)),
            RopsTree::Null => JsonValue::Null,
            RopsTree::Leaf(maybe_encrypted_value) => match maybe_encrypted_value {
                RopsMapEncryptedLeaf::Encrypted(encrypted_value) => JsonValue::String(encrypted_value.to_string()),
                RopsMapEncryptedLeaf::Escaped(escaped_value) => helpers::from_internal_value(escaped_value),
            },
        }
    }
}

mod helpers {
    use super::*;

    pub fn to_internal_number(number: serde_json::Number) -> Result<RopsValue, FormatToInternalMapError> {
        Ok(match number.is_f64() {
            true => RopsValue::Float(number.as_f64().expect("number not a f64").into()),
            false => RopsValue::Integer(
                number
                    .as_i64()
                    .ok_or_else(|| FormatToInternalMapError::IntegerOutOfRange(number.as_u64().expect("number not an u64")))?,
            ),
        })
    }

    pub fn from_internal_value(value: RopsValue) -> JsonValue {
        match value {
            RopsValue::String(string) => JsonValue::String(string),
            RopsValue::Boolean(bool) => JsonValue::Bool(bool),
            RopsValue::Integer(integer) => JsonValue::Number(integer.into()),
            // IMPROVEMENT: return Result instead
            RopsValue::Float(rops_float) => JsonValue::Number(
                serde_json::Number::from_f64(rops_float.into()).expect("invalid float, Infinite or NaN values are not valid JSON"),
            ),
        }
    }
}
