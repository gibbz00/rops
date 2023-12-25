use std::{fmt::Debug, str::FromStr};

use crate::*;

pub struct FromStrTestUtils;

impl FromStrTestUtils {
    pub fn assert_parse<T: MockTestUtil + MockDisplayTestUtil + FromStr + PartialEq + Debug>()
    where
        T::Err: Debug,
    {
        assert_eq!(T::mock(), T::mock_display().parse().unwrap())
    }
}
