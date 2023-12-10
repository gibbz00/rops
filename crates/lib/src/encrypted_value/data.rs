use derive_more::{AsRef, From};

use crate::*;

#[derive(Debug, PartialEq, AsRef, From)]
#[as_ref(forward)]
pub struct EncryptedValueData(Vec<u8>);

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for EncryptedValueData {
        fn mock() -> Self {
            Self(vec![221, 45, 68, 245, 169, 191])
        }
    }

    impl MockDisplayTestUtil for EncryptedValueData {
        fn mock_display() -> String {
            "3S1E9am/".to_string()
        }
    }
}
