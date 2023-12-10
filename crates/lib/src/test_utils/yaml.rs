use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

use crate::*;

pub trait MockYamlTestUtil {
    fn mock_yaml() -> String;
}

pub struct YamlTestUtils;

impl YamlTestUtils {
    pub fn assert_serialization<T: MockTestUtil + MockYamlTestUtil + Serialize>() {
        assert_eq!(T::mock_yaml(), serde_yaml::to_string(&T::mock()).unwrap())
    }

    pub fn assert_deserialization<T: MockTestUtil + MockYamlTestUtil + DeserializeOwned + Debug + PartialEq>() {
        assert_eq!(T::mock(), serde_yaml::from_str(&T::mock_yaml()).unwrap())
    }
}
