mod error_handling;
pub use error_handling::{RopsError, RopsResult};

mod rops_file;
pub use rops_file::*;

mod integration;
pub use integration::*;

mod encrypted_value;
pub use encrypted_value::*;

mod rng_key;
pub use rng_key::RngKey;

mod data_key;
pub use data_key::DataKey;

mod initial_value;
pub use initial_value::InitialValue;

mod value;
pub use value::ValueType;

mod cipher;
pub use cipher::*;

mod base64_utils;
pub use base64_utils::Base64Utils;

#[cfg(feature = "test-utils")]
mod mock;
#[cfg(feature = "test-utils")]
pub use mock::MockTestUtil;

#[cfg(feature = "test-utils")]
pub use display_test_utils::{DisplayTestUtils, MockStringTestUtil};
#[cfg(feature = "test-utils")]
mod display_test_utils {
    use std::fmt::Display;

    use crate::*;

    pub trait MockStringTestUtil {
        fn mock_string() -> String;
    }

    pub struct DisplayTestUtils;

    impl DisplayTestUtils {
        pub fn assert_display<T: MockTestUtil + Display + MockStringTestUtil + PartialEq>() {
            assert_eq!(T::mock_string(), T::mock().to_string())
        }
    }
}
