use clap::Parser;

use crate::*;

pub fn run() -> anyhow::Result<()> {
    let mut args = CliArgs::parse();
    args.merge_config(Config::retrieve(args.config_path())?);

    match args.cmd {
        CliSubcommand::Encrypt(encrypt_args) => Cli::encrypt(encrypt_args),
        CliSubcommand::Decrypt(decrypt_args) => Cli::decrypt(decrypt_args),
        CliSubcommand::Edit(input_args) => Cli::edit(input_args),
        CliSubcommand::Keys(key_command) => Cli::keys(key_command),
        CliSubcommand::Refresh(refresh_args) => Cli::refresh(refresh_args),
    }
}
