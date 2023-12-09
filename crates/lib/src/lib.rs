mod data_key;
pub use data_key::{DataKey, DATA_KEY_BYTE_SIZE};

mod error_handling;
pub use error_handling::{RopsError, RopsResult};

mod sops_file;
pub use sops_file::*;

mod integration;
pub use integration::*;

#[cfg(feature = "test-utils")]
pub use mocking::MockTestUtil;
#[cfg(all(feature = "test-utils", feature = "yaml"))]
pub use mocking::MockYamlTestUtil;
#[cfg(feature = "test-utils")]
mod mocking {
    pub trait MockTestUtil {
        fn mock() -> Self;
    }

    #[cfg(feature = "yaml")]
    pub trait MockYamlTestUtil {
        fn mock_yaml() -> String;
    }
}
