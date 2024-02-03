use std::fmt::{Debug, Display};

use serde::{de::DeserializeOwned, Serialize};

use crate::*;

pub trait MockFileFormatUtil<F: FileFormat> {
    fn mock_format_display() -> String;
}

pub struct FileFormatTestUtils;

impl FileFormatTestUtils {
    pub fn assert_serialization<F: FileFormat, T: MockTestUtil + MockFileFormatUtil<F> + Serialize>() {
        pretty_assertions::assert_eq!(T::mock_format_display(), F::serialize_to_string(&T::mock()).unwrap())
    }

    pub fn assert_deserialization<F: FileFormat, T: MockTestUtil + MockFileFormatUtil<F> + DeserializeOwned + Debug + PartialEq>() {
        pretty_assertions::assert_eq!(T::mock(), F::deserialize_from_str(&T::mock_format_display()).unwrap())
    }
}

pub trait FileFormatTestSuiteUtils: FileFormat {
    fn simple_map(key: impl Display, value: impl Display) -> String;

    fn key_value_map<S: RopsMapState>(key: impl Display, value: impl Display) -> RopsFileFormatMap<S, Self> {
        Self::create_format_map(&Self::simple_map(key, value))
    }

    fn create_format_map<S: RopsMapState>(key_value_str: &str) -> RopsFileFormatMap<S, Self> {
        RopsFileFormatMap::from_inner_map(Self::deserialize_from_str::<Self::Map>(key_value_str).unwrap())
    }
}
