use indexmap::IndexMap;
use serde_yaml::{Mapping as YamlMap, Value as YamlValue};

use crate::*;

mod tree_traversal {
    use super::*;

    pub fn recursive_map_call<F, S: RopsFileState>(yaml_map: YamlMap, recursive_value_fn: F) -> Result<RopsTree<S>, MapToTreeError>
    where
        F: Fn(YamlValue) -> Result<RopsTree<S>, MapToTreeError>,
    {
        let mut inner_map = IndexMap::default();

        for (yaml_key, value_yaml) in yaml_map {
            inner_map.insert(validate_key(yaml_key)?, recursive_value_fn(value_yaml)?);
        }

        return Ok(RopsTree::Map(inner_map));

        fn validate_key(yaml_value: YamlValue) -> Result<String, MapToTreeError> {
            match yaml_value {
                YamlValue::String(string) => Ok(string),
                other => Err(MapToTreeError::NonStringKey(
                    serde_yaml::to_string(&other).expect("yaml value not serializable"),
                )),
            }
        }
    }
}

mod encrypted {
    use super::*;

    impl<C: AeadCipher> TryFrom<RopsFileMap<Encrypted<C>, YamlFileFormat>> for RopsTree<Encrypted<C>> {
        type Error = MapToTreeError;

        fn try_from(rops_file_map: RopsFileMap<Encrypted<C>, YamlFileFormat>) -> Result<Self, Self::Error> {
            return tree_traversal::recursive_map_call(rops_file_map.into_inner_map(), recursive_value_call);

            fn recursive_value_call<Ci: AeadCipher>(yaml_value: YamlValue) -> Result<RopsTree<Encrypted<Ci>>, MapToTreeError> {
                Ok(match yaml_value {
                    YamlValue::Tagged(tagged) => recursive_value_call(tagged.value)?,
                    YamlValue::Mapping(map) => tree_traversal::recursive_map_call(map, recursive_value_call)?,
                    YamlValue::String(encrypted_string) => RopsTree::Leaf(encrypted_string.parse()?),
                    YamlValue::Sequence(sequence) => {
                        RopsTree::Sequence(sequence.into_iter().map(recursive_value_call).collect::<Result<Vec<_>, _>>()?)
                    }
                    YamlValue::Null => RopsTree::Null,
                    YamlValue::Bool(_) | YamlValue::Number(_) => {
                        // TEMP: handle as hard error until partial encryption support is added
                        return Err(MapToTreeError::InvalidValueForEncrypted(
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
                    RopsTree::mock(),
                    RopsFileMap::<Encrypted<AES256GCM>, YamlFileFormat>::mock().try_into().unwrap()
                )
            }
        }

        #[test]
        fn dissallows_non_string_keys() {
            let file_map = RopsFileMap::from_inner_map(serde_yaml::from_str::<YamlMap>("true: xxx").unwrap());
            assert!(matches!(
                RopsTree::<Encrypted<StubCipher>>::try_from(file_map).unwrap_err(),
                MapToTreeError::NonStringKey(_)
            ))
        }

        /*
            TEMP(NOTE): Not necassarily true once partial encryption arrives:
        */
        fn assert_disallowed_value_helper(key_value_str: &str) {
            let file_map = RopsFileMap::from_inner_map(serde_yaml::from_str::<YamlMap>(key_value_str).unwrap());
            assert!(matches!(
                RopsTree::<Encrypted<StubCipher>>::try_from(file_map).unwrap_err(),
                MapToTreeError::InvalidValueForEncrypted(_)
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

    impl TryFrom<RopsFileMap<Decrypted, YamlFileFormat>> for RopsTree<Decrypted> {
        type Error = MapToTreeError;

        fn try_from(rops_file_map: RopsFileMap<Decrypted, YamlFileFormat>) -> Result<Self, Self::Error> {
            return tree_traversal::recursive_map_call(rops_file_map.into_inner_map(), recursive_value_call);

            fn recursive_value_call(yaml_value: YamlValue) -> Result<RopsTree<Decrypted>, MapToTreeError> {
                Ok(match yaml_value {
                    // SOPS simply throws away tags, so do we for now.
                    // It can, however, deserialize manually added tags to encrypted documents,
                    // so we could in theory keep the tags somewhere without breaking SOPS compatability.
                    YamlValue::Tagged(tagged) => recursive_value_call(tagged.value)?,
                    YamlValue::Mapping(map) => tree_traversal::recursive_map_call(map, recursive_value_call)?,
                    YamlValue::Bool(boolean) => RopsTree::Leaf(RopsValue::Boolean(boolean)),
                    YamlValue::String(string) => RopsTree::Leaf(RopsValue::String(string)),
                    YamlValue::Number(number) => RopsTree::Leaf(match number.is_f64() {
                        true => RopsValue::Float(number.as_f64().expect("number not a f64")),
                        false => RopsValue::Integer(
                            number
                                .as_i64()
                                .ok_or_else(|| MapToTreeError::IntegerOutOfRange(number.as_u64().expect("number not an u64")))?,
                        ),
                    }),
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
                RopsTree::mock(),
                RopsFileMap::<Decrypted, YamlFileFormat>::mock().try_into().unwrap()
            )
        }

        #[test]
        fn dissallows_non_string_keys() {
            let file_map = RopsFileMap::from_inner_map(serde_yaml::from_str::<YamlMap>("123: 456").unwrap());
            assert!(matches!(
                RopsTree::<Decrypted>::try_from(file_map).unwrap_err(),
                MapToTreeError::NonStringKey(_)
            ))
        }

        #[test]
        fn dissallows_out_of_range_integers() {
            let file_map = RopsFileMap::from_inner_map(serde_yaml::from_str::<YamlMap>(&format!("invalid_integer: {}", u64::MAX)).unwrap());
            assert!(matches!(
                RopsTree::<Decrypted>::try_from(file_map).unwrap_err(),
                MapToTreeError::IntegerOutOfRange(_)
            ))
        }
    }
}