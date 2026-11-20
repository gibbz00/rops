#[cfg(feature = "test-utils")]
mod mock;

#[cfg(test)]
mod tests;

use indexmap::IndexMap;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use thiserror::Error;

use crate::*;

/// sops-compatible dotenv: one `KEY=VALUE` per line.
///
/// Plain keys hold the (encrypted or escaped) values. The sops metadata lives
/// under `sops_*` keys, with nested paths joined by `__` and list indices as
/// `list_N`, exactly as sops writes them (`sops_age__list_0__map_enc`). Values
/// are stored raw, so plain values cannot contain a newline; the PEM text in the
/// age recipients is stored with the two characters `\n` instead.
#[derive(Debug, PartialEq)]
pub struct DotenvFileFormat;

#[derive(Debug, Error)]
pub enum DotenvError {
    #[error("value of `{0}` contains a newline, which dotenv cannot store")]
    Newline(String),
    #[error("cannot use complex value in dotenv file; offending key {0}")]
    Complex(String),
    #[error("value of `{0}` is null; dotenv has no null")]
    Null(String),
    #[error("top-level value must be an object")]
    NotObject,
    #[error("line {0} is not KEY=VALUE")]
    Malformed(usize),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

const META_PREFIX: &str = "sops_";
const META_KEY: &str = "sops";
const SEPARATOR: &str = "__";

impl FileFormat for DotenvFileFormat {
    type Map = DotenvMap;

    type SerializeError = DotenvError;
    type DeserializeError = DotenvError;

    fn serialize_to_string<T: Serialize>(t: &T) -> Result<String, Self::SerializeError> {
        let JsonValue::Object(map) = serde_json::to_value(t)? else {
            return Err(DotenvError::NotObject);
        };
        let mut lines = Vec::new();
        for (key, value) in &map {
            if key == META_KEY {
                flatten_metadata(&mut Vec::new(), value, &mut lines)?;
            } else {
                lines.push(format!("{key}={}", plain_text(key, value)?));
            }
        }
        Ok(lines.join("\n") + "\n")
    }

    fn deserialize_from_str<T: DeserializeOwned>(str: &str) -> Result<T, Self::DeserializeError> {
        let mut root = JsonMap::new();
        let mut meta = JsonValue::Object(JsonMap::new());
        for (index, raw) in str.lines().enumerate() {
            let line = raw.trim_end_matches('\r');
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or(DotenvError::Malformed(index + 1))?;
            match key.strip_prefix(META_PREFIX) {
                Some(path) => {
                    // The first segment is a raw key of `sops`; later `map_` segments are map keys.
                    let segments: Vec<&str> = path
                        .split(SEPARATOR)
                        .enumerate()
                        .map(|(index, segment)| {
                            if index == 0 {
                                segment
                            } else {
                                segment.strip_prefix("map_").unwrap_or(segment)
                            }
                        })
                        .collect();
                    insert_path(&mut meta, &segments, typed_metadata(value));
                }
                None => {
                    root.insert(key.to_string(), JsonValue::String(value.to_string()));
                }
            }
        }
        if meta.as_object().is_some_and(|m| !m.is_empty()) {
            root.insert(META_KEY.to_string(), lists_from_indices(meta));
        }
        Ok(serde_json::from_value(JsonValue::Object(root))?)
    }
}

/// Dotenv's map. Its values are [`DotenvValue`], so the adapter impls are this module's.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DotenvMap(IndexMap<String, DotenvValue>);

impl IntoIterator for DotenvMap {
    type Item = (String, DotenvValue);
    type IntoIter = indexmap::map::IntoIter<String, DotenvValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FileFormatMapAdapter for DotenvMap {
    type Key = String;
    type Value = DotenvValue;

    fn with_capacity(capacity: usize) -> Self {
        DotenvMap(IndexMap::with_capacity(capacity))
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) {
        self.0.insert(key, value);
    }
}

/// Mirrors `serde_json::Value`, so the adapter below has the same arms as the JSON one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DotenvValue {
    Object(DotenvMap),
    Array(Vec<DotenvValue>),
    String(String),
    Bool(bool),
    Number(serde_json::Number),
    Null,
}

impl FileFormatValueAdapter for DotenvValue {
    fn decrypted_to_internal(self) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError> {
        Ok(match self {
            DotenvValue::Object(map) => RopsTree::Map(DotenvMap::decrypted_to_internal(map)?),
            DotenvValue::Bool(boolean) => RopsTree::Leaf(RopsValue::Boolean(boolean)),
            DotenvValue::String(string) => RopsTree::Leaf(RopsValue::String(string)),
            DotenvValue::Number(number) => RopsTree::Leaf(helpers::to_internal_number(number)?),
            DotenvValue::Array(sequence) => RopsTree::Sequence(
                sequence
                    .into_iter()
                    .map(Self::decrypted_to_internal)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            DotenvValue::Null => RopsTree::Null,
        })
    }

    fn decrypted_from_internal(rops_tree: RopsTree<DecryptedMap>) -> Self {
        match rops_tree {
            RopsTree::Sequence(sequence) => DotenvValue::Array(sequence.into_iter().map(Self::decrypted_from_internal).collect()),
            RopsTree::Map(map) => DotenvValue::Object(DotenvMap::decrypted_from_internal(map)),
            RopsTree::Null => DotenvValue::Null,
            RopsTree::Leaf(decrypted_value) => helpers::from_internal_value(decrypted_value),
        }
    }

    fn encrypted_to_internal<C: Cipher>(
        self,
        resolved_partial_encryption: ResolvedPartialEncryption,
    ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError> {
        Ok(match self {
            DotenvValue::Object(map) => RopsTree::Map(map.encrypted_to_internal(resolved_partial_encryption, Self::encrypted_to_internal)?),
            DotenvValue::String(string) => match resolved_partial_encryption.escape_encryption() || string.is_empty() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::String(string))),
                false => RopsTree::Leaf(RopsMapEncryptedLeaf::Encrypted(string.parse()?)),
            },
            DotenvValue::Array(sequence) => RopsTree::Sequence(
                sequence
                    .into_iter()
                    .map(|value| value.encrypted_to_internal(resolved_partial_encryption))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            DotenvValue::Null => RopsTree::Null,
            DotenvValue::Bool(bool) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::Boolean(bool))),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(bool.to_string())),
            },
            DotenvValue::Number(number) => match resolved_partial_encryption.escape_encryption() {
                true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(helpers::to_internal_number(number)?)),
                false => return Err(FormatToInternalMapError::PlaintextWhenEncrypted(number.to_string())),
            },
        })
    }

    fn encrypted_from_internal<C: Cipher>(internal_tree: RopsTree<EncryptedMap<C>>) -> Self {
        match internal_tree {
            RopsTree::Sequence(sequence) => DotenvValue::Array(sequence.into_iter().map(Self::encrypted_from_internal).collect()),
            RopsTree::Map(map) => DotenvValue::Object(DotenvMap::encrypted_from_internal(map)),
            RopsTree::Null => DotenvValue::Null,
            RopsTree::Leaf(maybe_encrypted_value) => match maybe_encrypted_value {
                RopsMapEncryptedLeaf::Encrypted(encrypted_value) => DotenvValue::String(encrypted_value.to_string()),
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

    pub fn from_internal_value(value: RopsValue) -> DotenvValue {
        match value {
            RopsValue::String(string) => DotenvValue::String(string),
            RopsValue::Boolean(bool) => DotenvValue::Bool(bool),
            RopsValue::Integer(integer) => DotenvValue::Number(integer.into()),
            // IMPROVEMENT: return Result instead
            RopsValue::Float(rops_float) => DotenvValue::Number(
                serde_json::Number::from_f64(rops_float.into()).expect("invalid float, Infinite or NaN values are not valid JSON"),
            ),
        }
    }
}

/// Scalars are written as text, like sops does (`N: 3` becomes `N=3`).
/// Lists and maps are refused with sops's error, never flattened.
fn plain_text(key: &str, value: &JsonValue) -> Result<String, DotenvError> {
    match value {
        JsonValue::String(text) if text.contains('\n') => Err(DotenvError::Newline(key.to_string())),
        JsonValue::String(text) => Ok(text.clone()),
        JsonValue::Bool(flag) => Ok(flag.to_string()),
        JsonValue::Number(number) => Ok(number.to_string()),
        JsonValue::Array(_) | JsonValue::Object(_) => Err(DotenvError::Complex(key.to_string())),
        JsonValue::Null => Err(DotenvError::Null(key.to_string())),
    }
}

fn flatten_metadata(path: &mut Vec<String>, value: &JsonValue, lines: &mut Vec<String>) -> Result<(), DotenvError> {
    match value {
        JsonValue::Object(map) => {
            // sops writes metadata keys sorted by name, not in struct order.
            let mut entries: Vec<(&String, &JsonValue)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (key, child) in entries {
                // sops prefixes map keys nested below the `sops` root with `map_`.
                let segment = if path.is_empty() { key.clone() } else { format!("map_{key}") };
                path.push(segment);
                flatten_metadata(path, child, lines)?;
                path.pop();
            }
        }
        JsonValue::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                path.push(format!("list_{index}"));
                flatten_metadata(path, child, lines)?;
                path.pop();
            }
        }
        JsonValue::Null => {}
        scalar => {
            let name = format!("{META_PREFIX}{}", path.join(SEPARATOR));
            let text = match scalar {
                JsonValue::String(text) => text.replace('\n', "\\n"),
                JsonValue::Bool(flag) => flag.to_string(),
                JsonValue::Number(number) => number.to_string(),
                _ => unreachable!("containers and null are handled above"),
            };
            lines.push(format!("{name}={text}"));
        }
    }
    Ok(())
}

/// Metadata values are unescaped and typed: `\n` back to a newline, `true` and
/// `false` as booleans, digits as numbers. Everything else stays a string.
fn typed_metadata(raw: &str) -> JsonValue {
    let text = raw.replace("\\n", "\n");
    match text.as_str() {
        "true" => JsonValue::Bool(true),
        "false" => JsonValue::Bool(false),
        digits if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => match digits.parse::<i64>() {
            Ok(number) => JsonValue::from(number),
            Err(_) => JsonValue::String(text),
        },
        _ => JsonValue::String(text),
    }
}

fn insert_path(node: &mut JsonValue, segments: &[&str], value: JsonValue) {
    let JsonValue::Object(map) = node else {
        return;
    };
    match segments {
        [] => {}
        [last] => {
            map.insert((*last).to_string(), value);
        }
        [head, rest @ ..] => {
            let child = map.entry((*head).to_string()).or_insert_with(|| JsonValue::Object(JsonMap::new()));
            insert_path(child, rest, value);
        }
    }
}

/// Turn objects whose keys are all `list_N` back into arrays, in index order.
fn lists_from_indices(node: JsonValue) -> JsonValue {
    match node {
        JsonValue::Object(map) => {
            let mut indexed: Vec<(usize, JsonValue)> = Vec::new();
            let is_list = !map.is_empty()
                && map
                    .iter()
                    .all(|(key, _)| key.strip_prefix("list_").and_then(|index| index.parse::<usize>().ok()).is_some());
            if is_list {
                for (key, child) in map {
                    let index = key["list_".len()..].parse::<usize>().expect("checked above");
                    indexed.push((index, lists_from_indices(child)));
                }
                indexed.sort_by_key(|(index, _)| *index);
                JsonValue::Array(indexed.into_iter().map(|(_, child)| child).collect())
            } else {
                JsonValue::Object(map.into_iter().map(|(key, child)| (key, lists_from_indices(child))).collect())
            }
        }
        other => other,
    }
}
