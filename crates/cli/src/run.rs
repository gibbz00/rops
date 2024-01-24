use clap::Parser;

use crate::*;

pub fn run() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    match args.cmd {
        CliSubcommand::Encrypt(encrypt_args) => Cli::encrypt(encrypt_args),
        CliSubcommand::Decrypt(decrypt_args) => Cli::decrypt(decrypt_args),
        CliSubcommand::Edit(input_args) => Cli::edit(input_args),
        CliSubcommand::Keys(key_args) => todo!(),
    }
}
