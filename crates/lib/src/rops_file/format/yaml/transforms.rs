use indexmap::IndexMap;
use serde_yaml::{Mapping as YamlMap, Value as YamlValue};

use crate::*;

mod tree_traversal {
    use super::*;

    pub fn recursive_map_call<F, S: RopsMapState>(yaml_map: YamlMap, recursive_value_fn: F) -> Result<RopsMap<S>, FormatToInternalMapError>
    where
        F: Fn(YamlValue) -> Result<RopsTree<S>, FormatToInternalMapError>,
    {
        let mut tree_map = IndexMap::default();

        for (yaml_key, value_yaml) in yaml_map {
            tree_map.insert(validate_key(yaml_key)?, recursive_value_fn(value_yaml)?);
        }

        return Ok(tree_map.into());

        fn validate_key(yaml_value: YamlValue) -> Result<String, FormatToInternalMapError> {
            match yaml_value {
                YamlValue::String(string) => Ok(string),
                other => Err(FormatToInternalMapError::NonStringKey(
                    serde_yaml::to_string(&other).expect("yaml value not serializable"),
                )),
            }
        }
    }
}

mod encrypted {
    use super::*;

    impl<C: Cipher> TryFrom<RopsFileFormatMap<EncryptedMap<C>, YamlFileFormat>> for RopsMap<EncryptedMap<C>> {
        type Error = FormatToInternalMapError;

        fn try_from(rops_file_map: RopsFileFormatMap<EncryptedMap<C>, YamlFileFormat>) -> Result<Self, Self::Error> {
            return tree_traversal::recursive_map_call(rops_file_map.into_inner_map(), recursive_value_call);

            fn recursive_value_call<Ci: Cipher>(yaml_value: YamlValue) -> Result<RopsTree<EncryptedMap<Ci>>, FormatToInternalMapError> {
                Ok(match yaml_value {
                    YamlValue::Tagged(tagged) => recursive_value_call(tagged.value)?,
                    YamlValue::Mapping(map) => RopsTree::Map(tree_traversal::recursive_map_call(map, recursive_value_call)?),
                    YamlValue::String(encrypted_string) => RopsTree::Leaf(encrypted_string.parse()?),
                    YamlValue::Sequence(sequence) => {
                        RopsTree::Sequence(sequence.into_iter().map(recursive_value_call).collect::<Result<Vec<_>, _>>()?)
                    }
                    YamlValue::Null => RopsTree::Null,
                    YamlValue::Bool(_) | YamlValue::Number(_) => {
                        // TEMP: handle as hard error until partial encryption support is added
                        return Err(FormatToInternalMapError::InvalidValueTypeForEncrypted(
                            serde_yaml::to_string(&yaml_value).expect("unable to serialize yaml value"),
                        ));
                    }
                })
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[cfg(feature = "aes-gcm")]
        mod aes_gcm {
            use super::*;

            #[test]
            fn transforms_encrypted_yaml_map() {
                assert_eq!(
                    RopsMap::mock(),
                    RopsFileFormatMap::<EncryptedMap<AES256GCM>, YamlFileFormat>::mock()
                        .try_into()
                        .unwrap()
                )
            }
        }

        #[test]
        fn dissallows_non_string_keys() {
            let file_map = RopsFileFormatMap::from_inner_map(serde_yaml::from_str::<YamlMap>("true: xxx").unwrap());
            assert!(matches!(
                RopsMap::<EncryptedMap<StubCipher>>::try_from(file_map).unwrap_err(),
                FormatToInternalMapError::NonStringKey(_)
            ))
        }

        /*
            TEMP(NOTE): Not necassarily true once partial encryption arrives:
        */
        fn assert_disallowed_value_helper(key_value_str: &str) {
            let file_map = RopsFileFormatMap::from_inner_map(serde_yaml::from_str::<YamlMap>(key_value_str).unwrap());
            assert!(matches!(
                RopsMap::<EncryptedMap<StubCipher>>::try_from(file_map).unwrap_err(),
                FormatToInternalMapError::InvalidValueTypeForEncrypted(_)
            ))
        }

        #[test]
        fn dissallows_boolean_values() {
            assert_disallowed_value_helper("disallowed_boolean: true")
        }

        #[test]
        fn dissallows_integer_values() {
            assert_disallowed_value_helper("disallowed_integer: 1")
        }
    }
}

mod decrypted {
    use super::*;

    mod to_interal {
        use super::*;

        impl TryFrom<RopsFileFormatMap<DecryptedMap, YamlFileFormat>> for RopsMap<DecryptedMap> {
            type Error = FormatToInternalMapError;

            fn try_from(rops_file_map: RopsFileFormatMap<DecryptedMap, YamlFileFormat>) -> Result<Self, Self::Error> {
                return tree_traversal::recursive_map_call(rops_file_map.into_inner_map(), recursive_value_call);

                fn recursive_value_call(yaml_value: YamlValue) -> Result<RopsTree<DecryptedMap>, FormatToInternalMapError> {
                    Ok(match yaml_value {
                        // SOPS simply throws away tags, so do we for now.
                        // It can, however, deserialize manually added tags to encrypted documents,
                        // so we could in theory keep the tags somewhere without breaking SOPS compatability.
                        YamlValue::Tagged(tagged) => recursive_value_call(tagged.value)?,
                        YamlValue::Mapping(map) => RopsTree::Map(tree_traversal::recursive_map_call(map, recursive_value_call)?),
                        YamlValue::Bool(boolean) => RopsTree::Leaf(RopsValue::Boolean(boolean)),
                        YamlValue::String(string) => RopsTree::Leaf(RopsValue::String(string)),
                        YamlValue::Number(number) => {
                            RopsTree::Leaf(match number.is_f64() {
                                true => RopsValue::Float(number.as_f64().expect("number not a f64").into()),
                                false => RopsValue::Integer(number.as_i64().ok_or_else(|| {
                                    FormatToInternalMapError::IntegerOutOfRange(number.as_u64().expect("number not an u64"))
                                })?),
                            })
                        }
                        YamlValue::Sequence(sequence) => {
                            RopsTree::Sequence(sequence.into_iter().map(recursive_value_call).collect::<Result<Vec<_>, _>>()?)
                        }
                        YamlValue::Null => RopsTree::Null,
                    })
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn transforms_decrypted_yaml_map() {
                assert_eq!(
                    RopsMap::mock(),
                    RopsFileFormatMap::<DecryptedMap, YamlFileFormat>::mock().try_into().unwrap()
                )
            }

            #[test]
            fn dissallows_non_string_keys() {
                let file_map = RopsFileFormatMap::from_inner_map(serde_yaml::from_str::<YamlMap>("123: 456").unwrap());
                assert!(matches!(
                    RopsMap::<DecryptedMap>::try_from(file_map).unwrap_err(),
                    FormatToInternalMapError::NonStringKey(_)
                ))
            }

            #[test]
            fn dissallows_out_of_range_integers() {
                let file_map =
                    RopsFileFormatMap::from_inner_map(serde_yaml::from_str::<YamlMap>(&format!("invalid_integer: {}", u64::MAX)).unwrap());
                assert!(matches!(
                    RopsMap::<DecryptedMap>::try_from(file_map).unwrap_err(),
                    FormatToInternalMapError::IntegerOutOfRange(_)
                ))
            }
        }
    }

    mod from_internal {
        use super::*;

        impl From<RopsMap<DecryptedMap>> for YamlMap {
            fn from(rops_map: RopsMap<DecryptedMap>) -> Self {
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
                        RopsTree::Leaf(decrypted_value) => match decrypted_value {
                            RopsValue::String(string) => YamlValue::String(string),
                            RopsValue::Boolean(bool) => YamlValue::Bool(bool),
                            RopsValue::Integer(integer) => YamlValue::Number(integer.into()),
                            RopsValue::Float(rops_float) => YamlValue::Number(f64::from(rops_float).into()),
                        },
                    }
                }
            }
        }
    }
}
