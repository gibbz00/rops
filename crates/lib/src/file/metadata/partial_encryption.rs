use derive_more::AsRef;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialEncryptionConfig {
    // Limit
    EncryptedSuffix(String),
    EncryptedRegex(RopsRegex),

    // Escape
    UnencryptedSuffix(String),
    UnencryptedRegex(RopsRegex),
}

#[derive(Default, Clone, Copy, AsRef)]
pub struct EscapeEncryption(pub bool);

impl PartialEncryptionConfig {
    pub fn resolve(&self, key_str: &str) -> ResolvedPartialEncryption {
        let maybe_escape_encryption: Option<EscapeEncryption> = match self {
            PartialEncryptionConfig::EncryptedSuffix(suffix) => key_str.ends_with(suffix).then_some(EscapeEncryption(false)),
            PartialEncryptionConfig::EncryptedRegex(regex) => regex.is_match(key_str).then_some(EscapeEncryption(false)),
            PartialEncryptionConfig::UnencryptedSuffix(suffix) => key_str.ends_with(suffix).then_some(EscapeEncryption(true)),
            PartialEncryptionConfig::UnencryptedRegex(regex) => regex.is_match(key_str).then_some(EscapeEncryption(true)),
        };

        match maybe_escape_encryption {
            Some(escape_encryption) => ResolvedPartialEncryption::Yes(escape_encryption),
            None => ResolvedPartialEncryption::No(self),
        }
    }
}

#[derive(Clone, Copy)]
pub enum ResolvedPartialEncryption<'a> {
    Yes(EscapeEncryption),
    No(&'a PartialEncryptionConfig),
}

impl ResolvedPartialEncryption<'_> {
    pub fn escape_encryption(&self) -> bool {
        match self {
            ResolvedPartialEncryption::Yes(escape_encryption) => escape_encryption.0,
            ResolvedPartialEncryption::No(partial_encryption_config) => match partial_encryption_config {
                PartialEncryptionConfig::EncryptedSuffix(_) | PartialEncryptionConfig::EncryptedRegex(_) => true,
                PartialEncryptionConfig::UnencryptedSuffix(_) | PartialEncryptionConfig::UnencryptedRegex(_) => false,
            },
        }
    }
}

impl<'a> From<Option<&'a PartialEncryptionConfig>> for ResolvedPartialEncryption<'a> {
    fn from(optional_partial_encryption_config: Option<&'a PartialEncryptionConfig>) -> Self {
        match optional_partial_encryption_config {
            Some(partial_encryption_config) => ResolvedPartialEncryption::No(partial_encryption_config),
            None => ResolvedPartialEncryption::Yes(EscapeEncryption(false)),
        }
    }
}

pub use regex::RopsRegex;
mod regex {
    use derive_more::{Deref, From, Into};
    use regex::Regex;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, Deref, From, Into)]
    #[serde(transparent)]
    pub struct RopsRegex(#[serde(with = "serde_regex")] Regex);

    // Should be OK for most purposes, mostly used for testing.
    impl PartialEq for RopsRegex {
        fn eq(&self, other: &Self) -> bool {
            self.0.as_str() == other.0.as_str()
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use std::sync::LazyLock;

    use crate::*;

    impl MockTestUtil for PartialEncryptionConfig {
        fn mock() -> Self {
            Self::UnencryptedSuffix(Self::mock_display())
        }
    }

    impl MockDisplayTestUtil for PartialEncryptionConfig {
        fn mock_display() -> String {
            "_unencrypted".to_string()
        }
    }

    static LAZY_PARTIAL_ENCRYPTION_CONFIG: LazyLock<PartialEncryptionConfig> = LazyLock::new(PartialEncryptionConfig::mock);

    impl MockTestUtil for ResolvedPartialEncryption<'_> {
        fn mock() -> Self {
            Self::No(&LAZY_PARTIAL_ENCRYPTION_CONFIG)
        }
    }

    impl MockTestUtil for Option<&PartialEncryptionConfig> {
        fn mock() -> Self {
            Some(&LAZY_PARTIAL_ENCRYPTION_CONFIG)
        }
    }
}
