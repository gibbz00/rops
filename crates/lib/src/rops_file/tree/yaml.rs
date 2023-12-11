use indexmap::IndexMap;
use serde_yaml::{Mapping as YamlMap, Value as YamlValue};

use crate::*;

impl TryFrom<YamlMap> for RopsTree {
    type Error = RopsTreeBuildError;

    fn try_from(yaml_map: YamlMap) -> Result<Self, Self::Error> {
        return recursive_map_call(yaml_map);

        fn recursive_map_call(yaml_map: YamlMap) -> Result<RopsTree, RopsTreeBuildError> {
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

        fn recursive_call(yaml_value: YamlValue) -> Result<RopsTree, RopsTreeBuildError> {
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

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockFileFormatUtil<YamlFileFormat> for YamlMap {
        fn mock_format_display() -> String {
            indoc::indoc! {"
                hello: world!
                nested_map:
                  null_key: null
                  array:
                  - string
                  - nested_map_in_array:
                      integer: 1234
                  - float: 1234.56789
                booleans:
                - true
                - false"
            }
            .to_string()
        }
    }

    impl MockTestUtil for YamlMap {
        fn mock() -> Self {
            serde_yaml::from_str(&YamlMap::mock_format_display()).expect("mock yaml string not serializable")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transforms_yaml_map() {
        assert_eq!(RopsTree::mock(), YamlMap::mock().try_into().unwrap())
    }

    #[test]
    fn dissallows_non_string_keys() {
        let yaml_map = serde_yaml::from_str::<YamlMap>("123: 456").unwrap();
        assert!(matches!(
            RopsTree::try_from(yaml_map).unwrap_err(),
            RopsTreeBuildError::NonStringKey(_)
        ))
    }

    #[test]
    fn dissallows_out_of_range_integers() {
        let yaml_map = serde_yaml::from_str::<YamlMap>(&format!("invalid_integer: {}", u64::MAX)).unwrap();
        assert!(matches!(
            RopsTree::try_from(yaml_map).unwrap_err(),
            RopsTreeBuildError::IntegerOutOfRange(_)
        ))
    }
}
