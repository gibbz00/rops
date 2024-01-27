use clap::{Parser, Subcommand};

use crate::*;

#[derive(Parser)]
pub struct CliArgs {
    #[command(subcommand)]
    pub cmd: CliSubcommand,
}

#[derive(Subcommand)]
pub enum CliSubcommand {
    #[command(visible_alias = "e")]
    Encrypt(EncryptArgs),
    #[command(visible_alias = "d")]
    Decrypt(DecryptArgs),
    /// Edit an encrypted rops file using $EDITOR. (Fallbacks to vim then nano and lastly vi.)
    /// Outputs to stdout if input is piped.
    Edit(EditArgs),
    /// Encrypted rops file key management.
    #[command(subcommand, visible_alias = "k")]
    Keys(KeysSubcommand),
}

impl ConfigArg for CliArgs {
    fn config_path(&self) -> Option<&std::path::Path> {
        match &self.cmd {
            CliSubcommand::Encrypt(sub_command) => sub_command.config_path(),
            CliSubcommand::Decrypt(sub_command) => sub_command.config_path(),
            CliSubcommand::Edit(sub_command) => sub_command.config_path(),
            CliSubcommand::Keys(sub_command) => sub_command.config_path(),
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
        }
    }
}
