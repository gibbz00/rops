use std::fmt::Display;

use crate::*;

impl FileFormatTestSuiteUtils for JsonFileFormat {
    fn simple_map(key: impl Display, value: impl Display) -> String {
        format!("{{\"{key}\":{value}}}")
    }
}

generate_file_format_test_suite!(JsonFileFormat);
