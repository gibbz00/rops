use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

use crate::*;

pub trait MockFileFormatUtil<F: FileFormat> {
    fn mock_format_display() -> String;
}

pub struct FileFormatTestUtils;

impl FileFormatTestUtils {
    pub fn assert_serialization<F: FileFormat, T: MockTestUtil + MockFileFormatUtil<F> + Serialize>() {
        assert_eq!(T::mock_format_display(), F::serialize_to_string(&T::mock()).unwrap())
    }

    pub fn assert_deserialization<F: FileFormat, T: MockTestUtil + MockFileFormatUtil<F> + DeserializeOwned + Debug + PartialEq>() {
        assert_eq!(T::mock(), F::deserialize_from_str(&T::mock_format_display()).unwrap())
    }
}
