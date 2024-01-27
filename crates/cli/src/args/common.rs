use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum, ValueHint};
use regex::Regex;
use rops::*;

use crate::*;

#[derive(Args)]
pub struct InputArgs {
    /// Read config from provided path
    #[arg(long, short, display_order = 0, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Required if no file argument is found to infer by extension
    #[arg(long, short, display_order = 20)]
    pub format: Option<Format>,
    /// Input may alternatively be supplied through stdin
    #[arg(value_hint = ValueHint::FilePath)]
    pub file: Option<PathBuf>,
}

impl ConfigArg for InputArgs {
    fn config_path(&self) -> Option<&Path> {
        self.config.as_deref()
    }
}

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
