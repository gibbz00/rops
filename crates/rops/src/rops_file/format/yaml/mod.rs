use indexmap::IndexMap;
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

    fn encrypted_to_internal<C: Cipher>(
        map: RopsFileFormatMap<EncryptedMap<C>, YamlFileFormat>,
        optional_partial_encryption_config: Option<&PartialEncryptionConfig>,
    ) -> Result<RopsMap<EncryptedMap<C>>, FormatToInternalMapError> {
        return recursive_map(map.into_inner_map(), optional_partial_encryption_config.into());

        fn recursive_map<Ci: Cipher>(
            map: YamlMap,
            resolved_partial_encryption: ResolvedPartialEncrpytion,
        ) -> Result<RopsMap<EncryptedMap<Ci>>, FormatToInternalMapError> {
            let mut tree_map = IndexMap::default();

            for (yaml_key, yaml_value) in map {
                let key_string = tree_traversal::validate_key(yaml_key)?;
                let mut resolved_partial_encryption = resolved_partial_encryption;

                if let ResolvedPartialEncrpytion::No(partial_encryption_config) = resolved_partial_encryption {
                    resolved_partial_encryption = partial_encryption_config.resolve(&key_string);
                }

                tree_map.insert(key_string, recursive_value_call(yaml_value, resolved_partial_encryption)?);
            }

            Ok(tree_map.into())
        }

        fn recursive_value_call<Ci: Cipher>(
            yaml_value: YamlValue,
            resolved_partial_encryption: ResolvedPartialEncrpytion,
        ) -> Result<RopsTree<EncryptedMap<Ci>>, FormatToInternalMapError> {
            Ok(match yaml_value {
                YamlValue::Tagged(tagged) => recursive_value_call(tagged.value, resolved_partial_encryption)?,
                YamlValue::Mapping(map) => RopsTree::Map(recursive_map(map, resolved_partial_encryption)?),
                YamlValue::String(string) => match resolved_partial_encryption.escape_encryption() {
                    true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::String(string))),
                    false => RopsTree::Leaf(RopsMapEncryptedLeaf::Encrypted(string.parse()?)),
                },
                YamlValue::Sequence(sequence) => RopsTree::Sequence(
                    sequence
                        .into_iter()
                        .map(|value| recursive_value_call(value, resolved_partial_encryption))
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
    }

    fn encrypted_from_internal<C: Cipher>(rops_map: RopsMap<EncryptedMap<C>>) -> Self::Map {
        return recursive_map(rops_map);

        fn recursive_map<Ci: Cipher>(rops_map: RopsMap<EncryptedMap<Ci>>) -> YamlMap {
            let mut yaml_map = YamlMap::with_capacity(rops_map.len());

            for (key, tree) in rops_map.0 {
                yaml_map.insert(YamlValue::String(key), recursive_tree(tree));
            }

            yaml_map
        }

        fn recursive_tree<Ci: Cipher>(internal_tree: RopsTree<EncryptedMap<Ci>>) -> YamlValue {
            match internal_tree {
                RopsTree::Sequence(sequence) => YamlValue::Sequence(sequence.into_iter().map(recursive_tree).collect()),
                RopsTree::Map(map) => YamlValue::Mapping(recursive_map(map)),
                RopsTree::Null => YamlValue::Null,
                RopsTree::Leaf(maybe_encrypted_value) => match maybe_encrypted_value {
                    RopsMapEncryptedLeaf::Encrypted(encrypted_value) => YamlValue::String(encrypted_value.to_string()),
                    RopsMapEncryptedLeaf::Escaped(escaped_value) => tree_traversal::internal_to_yaml_value(escaped_value),
                },
            }
        }
    }

    fn decrypted_to_internal(format_map: RopsFileFormatMap<DecryptedMap, Self>) -> Result<RopsMap<DecryptedMap>, FormatToInternalMapError> {
        return tree_traversal::recursive_map_call(format_map.into_inner_map(), recursive_value_call);

        fn recursive_value_call(yaml_value: YamlValue) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError> {
            Ok(match yaml_value {
                // SOPS simply throws away tags, so do we for now.
                // It can, however, deserialize manually added tags to encrypted documents,
                // so we could in theory keep the tags somewhere without breaking SOPS compatability.
                YamlValue::Tagged(tagged) => recursive_value_call(tagged.value)?,
                YamlValue::Mapping(map) => RopsTree::Map(tree_traversal::recursive_map_call(map, recursive_value_call)?),
                YamlValue::Bool(boolean) => RopsTree::Leaf(RopsValue::Boolean(boolean)),
                YamlValue::String(string) => RopsTree::Leaf(RopsValue::String(string)),
                YamlValue::Number(number) => RopsTree::Leaf(tree_traversal::resolve_number(number)?),
                YamlValue::Sequence(sequence) => {
                    RopsTree::Sequence(sequence.into_iter().map(recursive_value_call).collect::<Result<Vec<_>, _>>()?)
                }
                YamlValue::Null => RopsTree::Null,
            })
        }
    }

    fn decrypted_from_internal(rops_map: RopsMap<DecryptedMap>) -> Self::Map {
        return recursive_map(rops_map);

        fn recursive_map(rops_map: RopsMap<DecryptedMap>) -> YamlMap {
            let mut yaml_map = YamlMap::with_capacity(rops_map.len());

            for (key, value) in rops_map.0 {
                yaml_map.insert(YamlValue::String(key), recursive_tree(value));
            }

            yaml_map
        }

        fn recursive_tree(rops_tree: RopsTree<DecryptedMap>) -> YamlValue {
            match rops_tree {
                RopsTree::Sequence(sequence) => YamlValue::Sequence(sequence.into_iter().map(recursive_tree).collect()),
                RopsTree::Map(map) => YamlValue::Mapping(recursive_map(map)),
                RopsTree::Null => YamlValue::Null,
                RopsTree::Leaf(decrypted_value) => tree_traversal::internal_to_yaml_value(decrypted_value),
            }
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

    pub fn recursive_map_call<F, S: RopsMapState>(yaml_map: YamlMap, recursive_value_fn: F) -> Result<RopsMap<S>, FormatToInternalMapError>
    where
        F: Fn(YamlValue) -> Result<RopsTree<S>, FormatToInternalMapError>,
    {
        let mut tree_map = IndexMap::default();

        for (yaml_key, value_yaml) in yaml_map {
            let key_string = validate_key(yaml_key)?;

            tree_map.insert(key_string, recursive_value_fn(value_yaml)?);
        }

        Ok(tree_map.into())
    }

    pub fn validate_key(yaml_value: YamlValue) -> Result<String, FormatToInternalMapError> {
        match yaml_value {
            YamlValue::String(string) => Ok(string),
            other => Err(FormatToInternalMapError::NonStringKey(
                serde_yaml::to_string(&other).expect("yaml value not serializable"),
            )),
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock;

#[cfg(test)]
mod tests;
