use clap::{Args, ValueEnum};
use regex::Regex;
use rops::*;

#[derive(Args)]
#[group(id = "partial_encryption", multiple = false)]
pub struct PartialEncryptionArgs {
    /// Encrypt values matching key suffix
    #[arg(long, display_order = 10, value_name = "STRING")]
    encrypted_suffix: Option<String>,
    /// Encrypt values matching key regex
    #[arg(long, display_order = 10, value_name = "REGEX")]
    encrypted_regex: Option<Regex>,
    /// Skip encrypting values matching key suffix
    #[arg(long, display_order = 10, value_name = "STRING")]
    unencrypted_suffix: Option<String>,
    /// Skip encrypting values matching key regex
    #[arg(long, display_order = 10, value_name = "REGEX")]
    unencrypted_regex: Option<Regex>,
}

impl From<PartialEncryptionArgs> for PartialEncryptionConfig {
    fn from(partial_encryption_args: PartialEncryptionArgs) -> Self {
        #[rustfmt::skip]
        let PartialEncryptionArgs { encrypted_suffix, encrypted_regex, unencrypted_suffix, unencrypted_regex } = partial_encryption_args;

        encrypted_suffix
            .map(PartialEncryptionConfig::EncryptedSuffix)
            .or_else(|| encrypted_regex.map(Into::into).map(PartialEncryptionConfig::EncryptedRegex))
            .or_else(|| unencrypted_suffix.map(PartialEncryptionConfig::UnencryptedSuffix))
            .or_else(|| unencrypted_regex.map(Into::into).map(PartialEncryptionConfig::UencryptedRegex))
            // from #[group(multiple = true)]
            .expect("at least one partial encryption arg must be set")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum Format {
    #[value(alias = "yml")]
    Yaml,
    Json,
    Toml,
}
