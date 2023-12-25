use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum PartialEncryption {
    // Limit
    #[serde(rename = "encrypted_suffix")]
    EncryptedSuffix(String),
    #[serde(rename = "encrypted_regex")]
    EncryptedRegex(RopsRegex),

    // Escape
    #[serde(rename = "unencrypted_suffix")]
    UnencryptedSuffix(String),
    #[serde(rename = "unencrypted_regex")]
    UencryptedRegex(RopsRegex),
}

pub use regex::RopsRegex;
mod regex {
    use regex::Regex;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct RopsRegex(#[serde(with = "serde_regex")] Regex);

    impl PartialEq for RopsRegex {
        fn eq(&self, other: &Self) -> bool {
            self.0.as_str() == other.0.as_str()
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use crate::*;

    impl MockTestUtil for PartialEncryption {
        fn mock() -> Self {
            Self::UnencryptedSuffix(Self::mock_display())
        }
    }

    impl MockDisplayTestUtil for PartialEncryption {
        fn mock_display() -> String {
            "_unencrypted".to_string()
        }
    }
}
