mod data_key;
pub use data_key::{DataKey, DATA_KEY_BYTE_SIZE};

mod error_handling;
pub use error_handling::{RopsError, RopsResult};

mod integration;
pub use integration::*;

#[cfg(feature = "test-utils")]
pub use test_utils::MockTestUtil;
#[cfg(feature = "test-utils")]
mod test_utils {
    pub trait MockTestUtil {
        fn mock() -> Self;
    }
}
