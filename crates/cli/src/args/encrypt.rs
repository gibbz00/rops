use clap::{ArgAction, Args};
use rops::*;

use crate::*;

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
