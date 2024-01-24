use clap::{ArgAction, Args};

use crate::*;

#[derive(Args)]
pub struct EncryptArgs {
    #[command(flatten)]
    pub intregration_keys: IntegrationKeys,
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
