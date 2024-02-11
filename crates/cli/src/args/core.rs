use clap::{Parser, Subcommand};

use crate::*;

#[derive(Parser)]
pub struct CliArgs {
    #[command(subcommand)]
    pub cmd: CliSubcommand,
}

#[derive(Subcommand)]
pub enum CliSubcommand {
    /// Encrypt plaintext maps
    #[command(visible_alias = "e")]
    Encrypt(EncryptArgs),
    /// Decrypt rops files
    #[command(visible_alias = "d")]
    Decrypt(DecryptArgs),
    /// Edit an encrypted rops file using $EDITOR. (Fallbacks to vim then nano and lastly vi.)
    /// Outputs to stdout if input is piped
    Edit(EditArgs),
    /// Manage encrypted rops file keys
    #[command(subcommand, visible_alias = "k")]
    Keys(KeysSubcommand),
    /// Make a config the single source of configuration truth for an encrypted rops file
    Refresh(RefreshArgs),
}

impl ConfigArg for CliArgs {
    fn config_path(&self) -> Option<&std::path::Path> {
        match &self.cmd {
            CliSubcommand::Encrypt(sub_command) => sub_command.config_path(),
            CliSubcommand::Decrypt(sub_command) => sub_command.config_path(),
            CliSubcommand::Edit(sub_command) => sub_command.config_path(),
            CliSubcommand::Keys(sub_command) => sub_command.config_path(),
            CliSubcommand::Refresh(sub_command) => sub_command.config_path(),
        }
    }
}

impl MergeConfig for CliArgs {
    fn merge_config(&mut self, config: Config) {
        match &mut self.cmd {
            CliSubcommand::Encrypt(sub_command) => sub_command.merge_config(config),
            CliSubcommand::Decrypt(sub_command) => sub_command.merge_config(config),
            CliSubcommand::Edit(sub_command) => sub_command.merge_config(config),
            CliSubcommand::Keys(sub_command) => sub_command.merge_config(config),
            CliSubcommand::Refresh(sub_command) => sub_command.merge_config(config),
        }
    }
}
