use std::fmt::Display;

use crate::*;

impl FileFormatTestSuiteUtils for TomlFileFormat {
    fn simple_map(key: impl Display, value: impl Display) -> String {
        format!("{key} = {value}")
    }
}

generate_file_format_test_suite!(TomlFileFormat);
