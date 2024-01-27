use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueHint};

use crate::*;

#[derive(Subcommand)]
pub enum KeysSubcommand {
    Add(KeyInputArgs),
    Remove(KeyInputArgs),
}

#[derive(Args)]
pub struct KeyInputArgs {
    #[command(flatten)]
    pub intregration_keys: IntegrationKeys,
    /// Required unless it can be inferred from the file argument.
    #[arg(long, short)]
    pub format: Option<Format>,
    /// Path to an encrypted rops file.
    #[arg(value_hint = ValueHint::FilePath)]
    pub file: PathBuf,
}

impl ConfigArg for KeysSubcommand {
    fn config_path(&self) -> Option<&Path> {
        None
    }
}

impl MergeConfig for KeysSubcommand {
    fn merge_config(&mut self, _config: Config) {
        // todo!()
    }
}
