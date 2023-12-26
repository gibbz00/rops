use derive_more::AsRef;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum PartialEncryptionConfig {
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

#[derive(Default, Clone, Copy, AsRef)]
pub struct EscapeEncryption(pub bool);

impl PartialEncryptionConfig {
    pub fn resolve(&self, key_str: &str) -> ResolvedPartialEncrpytion {
        let maybe_escape_encryption: Option<EscapeEncryption> = match self {
            PartialEncryptionConfig::EncryptedSuffix(suffix) => key_str.ends_with(suffix).then_some(EscapeEncryption(false)),
            PartialEncryptionConfig::EncryptedRegex(regex) => regex.is_match(key_str).then_some(EscapeEncryption(false)),
            PartialEncryptionConfig::UnencryptedSuffix(suffix) => key_str.ends_with(suffix).then_some(EscapeEncryption(true)),
            PartialEncryptionConfig::UencryptedRegex(regex) => regex.is_match(key_str).then_some(EscapeEncryption(true)),
        };

        match maybe_escape_encryption {
            Some(escape_encryption) => ResolvedPartialEncrpytion::Yes(escape_encryption),
            None => ResolvedPartialEncrpytion::No(self),
        }
    }
}

#[derive(Clone, Copy)]
pub enum ResolvedPartialEncrpytion<'a> {
    Yes(EscapeEncryption),
    No(&'a PartialEncryptionConfig),
}

impl ResolvedPartialEncrpytion<'_> {
    pub fn escape_encryption(&self) -> bool {
        match self {
            ResolvedPartialEncrpytion::Yes(escape_encryption) => escape_encryption.0,
            ResolvedPartialEncrpytion::No(_) => false,
        }
    }
}

impl<'a> From<Option<&'a PartialEncryptionConfig>> for ResolvedPartialEncrpytion<'a> {
    fn from(optional_partial_encryption_config: Option<&'a PartialEncryptionConfig>) -> Self {
        match optional_partial_encryption_config {
            Some(partial_encryption_config) => ResolvedPartialEncrpytion::No(partial_encryption_config),
            None => ResolvedPartialEncrpytion::Yes(EscapeEncryption(false)),
        }
    }
}

pub use regex::RopsRegex;
mod regex {
    use derive_more::{Deref, From};
    use regex::Regex;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, Deref, From)]
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
}
