use clap::{ArgAction, Args};

use crate::*;

#[derive(Args)]
pub struct DecryptArgs {
    #[command(flatten)]
    pub input_args: InputArgs,
    #[arg(long, short, requires = "file", action(ArgAction::SetTrue))]
    /// Decrypt file in place rather than printing the result to stdout, metadata excluded
    pub in_place: Option<bool>,
}
