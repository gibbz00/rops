use std::str::FromStr;

use derive_more::{AsMut, AsRef, From, Into};

use crate::*;

#[derive(Debug, PartialEq, AsRef, AsMut, From, Into)]
#[as_ref(forward)]
#[as_mut(forward)]
pub struct EncryptedData(Vec<u8>);

impl FromStr for EncryptedData {
    type Err = Base64DecodeError;

    fn from_str(base64_str: &str) -> Result<Self, Self::Err> {
        let mut buffer = Vec::with_capacity(::base64::decoded_len_estimate(base64_str.len()));
        buffer.decode_base64(base64_str).map(|_| buffer.into())
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for EncryptedData {
        fn mock() -> Self {
            Self(vec![221, 45, 68, 245, 169, 191])
        }
    }

    impl MockDisplayTestUtil for EncryptedData {
        fn mock_display() -> String {
            "3S1E9am/".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_base64_str() {
        FromStrTestUtils::assert_parse::<EncryptedData>()
    }
}
