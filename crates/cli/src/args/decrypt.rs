use std::path::Path;

use clap::{ArgAction, Args};

use crate::*;

#[derive(Args)]
pub struct DecryptArgs {
    #[command(flatten)]
    pub input_args: InputArgs,
    #[arg(long, short, requires = "file", action(ArgAction::SetTrue), display_order = 0)]
    /// Decrypt file in place rather than printing the result to stdout, metadata excluded
    pub in_place: Option<bool>,
}

impl ConfigArg for DecryptArgs {
    fn config_path(&self) -> Option<&Path> {
        self.input_args.config_path()
    }
}

impl MergeConfig for DecryptArgs {
    fn merge_config(&mut self, _config: Config) {
        // todo!()
    }
}
