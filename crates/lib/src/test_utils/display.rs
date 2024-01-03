use std::fmt::Display;

use crate::*;

pub trait MockDisplayTestUtil {
    fn mock_display() -> String;
}

pub struct DisplayTestUtils;

impl DisplayTestUtils {
    pub fn assert_display<T: MockTestUtil + Display + MockDisplayTestUtil + PartialEq>() {
        pretty_assertions::assert_eq!(T::mock_display(), T::mock().to_string())
    }
}
