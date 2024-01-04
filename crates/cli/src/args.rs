use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum, ValueHint};
use regex::Regex;
use rops::*;

#[derive(Parser)]
pub struct CliArgs {
    #[command(subcommand)]
    pub cmd: CliCommand,
}

// use rops::RopsFileBuilder;
#[derive(Subcommand)]
pub enum CliCommand {
    #[command(visible_alias = "e")]
    Encrypt(EncryptArgs),
    #[command(visible_alias = "d")]
    Decrypt(InputArgs),
}

#[derive(Args)]
pub struct EncryptArgs {
    /// Space separated list of public age keys
    #[arg(long = "age")]
    pub age_keys: Vec<<AgeIntegration as Integration>::KeyId>,
    #[command(flatten)]
    pub partial_encryption_args: Option<PartialEncryptionArgs>,
    #[command(flatten)]
    pub input_args: InputArgs,
}

#[derive(Args)]
pub struct InputArgs {
    /// Required if no file argument is found to infer by extension.
    #[arg(long, short, display_order = 20)]
    pub format: Option<Format>,
    /// Input may alternatively be supplied through stdin.
    #[arg(value_hint = ValueHint::FilePath)]
    pub file: Option<PathBuf>,
}

#[derive(Args)]
#[group(multiple = false)]
pub struct PartialEncryptionArgs {
    #[arg(long, display_order = 10, value_name = "STRING")]
    encrypted_suffix: Option<String>,
    #[arg(long, display_order = 10, value_name = "REGEX")]
    encrypted_regex: Option<Regex>,
    #[arg(long, display_order = 10, value_name = "STRING")]
    unencrypted_suffix: Option<String>,
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
            // #[group(multiple = true)]
            .expect("at least one partial encryption arg must be set")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum Format {
    #[value(alias = "yml")]
    Yaml,
    Json,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn verify_args() {
        CliArgs::command().debug_assert()
    }
}
