use indexmap::IndexMap;
use serde_yaml::{Mapping as YamlMap, Value as YamlValue};

use crate::*;

impl TryFrom<RopsFileMap<Decrypted, YamlFileFormat>> for RopsTree<Decrypted> {
    type Error = RopsTreeBuildError;

    fn try_from(rops_file_map: RopsFileMap<Decrypted, YamlFileFormat>) -> Result<Self, Self::Error> {
        return recursive_map_call(rops_file_map.into_inner_map());

        fn recursive_map_call(yaml_map: YamlMap) -> Result<RopsTree<Decrypted>, RopsTreeBuildError> {
            let mut inner_map = IndexMap::default();

            for (yaml_key, value_yaml) in yaml_map {
                inner_map.insert(validate_key(yaml_key)?, recursive_call(value_yaml)?);
            }

            return Ok(RopsTree::Map(inner_map));

            fn validate_key(yaml_value: YamlValue) -> Result<String, RopsTreeBuildError> {
                match yaml_value {
                    YamlValue::String(string) => Ok(string),
                    other => Err(RopsTreeBuildError::NonStringKey(
                        serde_yaml::to_string(&other).expect("yaml value not serializable"),
                    )),
                }
            }
        }

        fn recursive_call(yaml_value: YamlValue) -> Result<RopsTree<Decrypted>, RopsTreeBuildError> {
            Ok(match yaml_value {
                // SOPS simply throws away tags, so do we for now.
                // It can, however, deserialize manually added tags to encrypted documents,
                // so we could in theory keep the tags somewhere without breaking SOPS compatability.
                YamlValue::Tagged(tagged) => recursive_call(tagged.value)?,
                YamlValue::Mapping(map) => recursive_map_call(map)?,
                YamlValue::Bool(boolean) => RopsTree::Leaf(RopsValue::Boolean(boolean)),
                YamlValue::String(string) => RopsTree::Leaf(RopsValue::String(string)),
                YamlValue::Number(number) => RopsTree::Leaf(match number.is_f64() {
                    true => RopsValue::Float(number.as_f64().expect("number not a f64")),
                    false => RopsValue::Integer(
                        number
                            .as_i64()
                            .ok_or_else(|| RopsTreeBuildError::IntegerOutOfRange(number.as_u64().expect("number not an u64")))?,
                    ),
                }),
                YamlValue::Sequence(sequence) => {
                    RopsTree::Sequence(sequence.into_iter().map(recursive_call).collect::<Result<Vec<_>, _>>()?)
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
            RopsTree::try_from(file_map).unwrap_err(),
            RopsTreeBuildError::NonStringKey(_)
        ))
    }

    #[test]
    fn dissallows_out_of_range_integers() {
        let file_map = RopsFileMap::from_inner_map(serde_yaml::from_str::<YamlMap>(&format!("invalid_integer: {}", u64::MAX)).unwrap());
        assert!(matches!(
            RopsTree::try_from(file_map).unwrap_err(),
            RopsTreeBuildError::IntegerOutOfRange(_)
        ))
    }
}
