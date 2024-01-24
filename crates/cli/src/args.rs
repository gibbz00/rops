use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum, ValueHint};
use regex::Regex;
use rops::*;

#[derive(Parser)]
pub struct CliArgs {
    #[command(subcommand)]
    pub cmd: CliSubcommand,
}

// use rops::RopsFileBuilder;
#[derive(Subcommand)]
pub enum CliSubcommand {
    #[command(visible_alias = "e")]
    Encrypt(EncryptArgs),
    #[command(visible_alias = "d")]
    Decrypt(DecryptArgs),
    /// Edit an encrypted rops file using $EDITOR. (Fallbacks to vim then nano and lastly vi.)
    /// Outputs to stdout if input is piped.
    Edit(InputArgs),
}

#[derive(Args)]
pub struct EncryptArgs {
    /// Space separated list of public age keys
    #[arg(long = "age")]
    pub age_keys: Vec<<AgeIntegration as Integration>::KeyId>,
    /// Space separated list of AWS KMS rops key id strings.
    #[arg(long = "aws-kms")]
    pub aws_kms_keys: Vec<<AwsKmsIntegration as Integration>::KeyId>,
    #[command(flatten)]
    pub partial_encryption_args: Option<PartialEncryptionArgs>,
    /// Requires a partial encryption setting
    #[arg(long, display_order = 11, requires = "partial_encryption", action(ArgAction::SetTrue))]
    pub mac_only_encrypted: Option<bool>,
    #[command(flatten)]
    pub input_args: InputArgs,
    #[arg(long, short, requires = "file", action(ArgAction::SetTrue))]
    /// Encrypt file in place rather than printing the result to stdout.
    pub in_place: Option<bool>,
}

#[derive(Args)]
pub struct DecryptArgs {
    #[command(flatten)]
    pub input_args: InputArgs,
    #[arg(long, short, requires = "file", action(ArgAction::SetTrue))]
    /// Decrypt file in place rather than printing the result to stdout, metadata excluded
    pub in_place: Option<bool>,
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
#[group(id = "partial_encryption", multiple = false)]
pub struct PartialEncryptionArgs {
    /// Encrypt values matching key suffix.
    #[arg(long, display_order = 10, value_name = "STRING")]
    encrypted_suffix: Option<String>,
    /// Encrypt values matching key regex.
    #[arg(long, display_order = 10, value_name = "REGEX")]
    encrypted_regex: Option<Regex>,
    /// Skip encrypting values matching key suffix.
    #[arg(long, display_order = 10, value_name = "STRING")]
    unencrypted_suffix: Option<String>,
    /// Skip encrypting values matching key regex.
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
