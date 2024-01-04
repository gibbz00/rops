use std::path::PathBuf;

use clap::{Args, Parser, ValueEnum, ValueHint};
use rops::*;

#[derive(Parser)]
pub struct CliArgs {
    #[command(subcommand)]
    pub cmd: CliCommand,
    /// Required if no file argument is found.
    ///
    /// May otherwise be inferred by a given file extension.
    #[arg(long, short, global = true)]
    pub format: Option<Format>,
    /// Input may alternatively be supplied through stdin.
    #[arg(global = true, value_hint = ValueHint::FilePath)]
    pub file: Option<PathBuf>,
}

// use rops::RopsFileBuilder;
#[derive(Parser)]
pub enum CliCommand {
    Encrypt(EncryptArgs),
    Decrypt,
}

#[derive(Args)]
pub struct EncryptArgs {
    /// Space separated list of public age keys
    #[arg(long = "age")]
    pub age_keys: Vec<<AgeIntegration as Integration>::KeyId>,
}

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum Format {
    #[value(alias = "yml")]
    Yaml,
    Json,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn verify_args() {
        CliArgs::command().debug_assert()
    }
}
