use std::path::Path;

use clap::{ArgAction, Args};

use crate::*;

#[derive(Args)]
pub struct RefreshArgs {
    #[command(flatten)]
    pub input_args: InputArgs,
    /// Refresh the file in place rather than printing the result to stdout.
    #[arg(long, short, requires = "file", action(ArgAction::SetTrue), display_order = 0)]
    pub in_place: Option<bool>,
}

impl ConfigArg for RefreshArgs {
    fn config_path(&self) -> Option<&Path> {
        self.input_args.config_path()
    }
}

impl MergeConfig for RefreshArgs {
    fn merge_config(&mut self, _config: Config) {
        // todo!()
    }
}
