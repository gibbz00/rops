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

    fn finalize_rops_file_string(serialized: String) -> String {
        quote_last_modified(serialized)
    }
}

/// `serde_yaml` does not quote strings that look like timestamps, which yields
/// `lastmodified: 2023-12-26T17:50:08Z`. SOPS writes the value quoted, so the
/// metadata timestamp is wrapped in double quotes to match its output.
///
/// Only the `lastmodified` entry directly inside the top-level `sops:` block is
/// touched; user data is left as is.
fn quote_last_modified(yaml: String) -> String {
    const METADATA_KEY: &str = "sops:";
    const KEY: &str = "lastmodified: ";

    let mut output = String::with_capacity(yaml.len() + 2);
    let mut in_metadata = false;
    let mut metadata_indent: Option<usize> = None;

    for line in yaml.split_inclusive('\n') {
        let content = line.trim_end_matches(['\n', '\r']);
        let line_ending = &line[content.len()..];
        let trimmed = content.trim_start();
        let indent_len = content.len() - trimmed.len();

        if indent_len == 0 && !trimmed.is_empty() {
            in_metadata = trimmed == METADATA_KEY;
            metadata_indent = None;
            output.push_str(line);
            continue;
        }

        if in_metadata && !trimmed.is_empty() {
            let direct_child_indent = *metadata_indent.get_or_insert(indent_len);

            let quoted = (indent_len == direct_child_indent)
                .then(|| trimmed.strip_prefix(KEY))
                .flatten()
                .filter(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok())
                .map(|value| format!("{}{KEY}\"{value}\"{line_ending}", &content[..indent_len]));

            if let Some(quoted) = quoted {
                output.push_str(&quoted);
                continue;
            }
        }

        output.push_str(line);
    }

    output
}

#[cfg(test)]
mod quote_last_modified_tests {
    use super::quote_last_modified;

    #[test]
    fn quotes_metadata_last_modified_only() {
        let input = indoc::indoc! {"
            lastmodified: 2020-01-01T00:00:00Z
            nested:
              lastmodified: 2020-01-01T00:00:00Z
            sops:
              age:
              - recipient: age1abc
                lastmodified: 2020-01-01T00:00:00Z
              lastmodified: 2023-12-26T17:50:08Z
              mac: ENC[...]
        "};

        let expected = indoc::indoc! {"
            lastmodified: 2020-01-01T00:00:00Z
            nested:
              lastmodified: 2020-01-01T00:00:00Z
            sops:
              age:
              - recipient: age1abc
                lastmodified: 2020-01-01T00:00:00Z
              lastmodified: \"2023-12-26T17:50:08Z\"
              mac: ENC[...]
        "};

        assert_eq!(expected, quote_last_modified(input.to_string()));
    }

    #[test]
    fn leaves_already_quoted_value_untouched() {
        let input = "sops:\n  lastmodified: \"2023-12-26T17:50:08Z\"\n";
        assert_eq!(input, quote_last_modified(input.to_string()));
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
            // so we could in theory keep the tags somewhere without breaking SOPS compatibility.
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
        resolved_partial_encryption: ResolvedPartialEncryption,
    ) -> Result<RopsTree<EncryptedMap<C>>, FormatToInternalMapError> {
        Ok(match self {
            YamlValue::Tagged(tagged) => tagged.value.encrypted_to_internal(resolved_partial_encryption)?,
            YamlValue::Mapping(map) => RopsTree::Map(map.encrypted_to_internal(resolved_partial_encryption, Self::encrypted_to_internal)?),
            YamlValue::String(string) => match resolved_partial_encryption.escape_encryption() || string.is_empty() {
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
