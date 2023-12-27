use std::fmt::Display;

use crate::*;

impl FileFormatTestSuiteUtils for YamlFileFormat {
    fn key_value_string(key: impl Display, value: impl Display) -> String {
        format!("{}: {}", key, value)
    }

    fn create_format_map<S: RopsMapState>(key_value_str: &str) -> RopsFileFormatMap<S, Self> {
        RopsFileFormatMap::from_inner_map(serde_yaml::from_str::<serde_yaml::Mapping>(key_value_str).unwrap())
    }
}

generate_file_format_test_suite!(YamlFileFormat);
