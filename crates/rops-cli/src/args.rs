use std::path::PathBuf;

use clap::{Args, Parser, ValueEnum};
use rops::*;

// use rops::RopsFileBuilder;
#[derive(Parser)]
pub enum CliArgs {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

#[derive(Args)]
pub struct EncryptArgs {
    /// Space separated list of public age keys
    #[arg(long = "age")]
    pub age_keys: Vec<<AgeIntegration as Integration>::KeyId>,
    #[arg(long, short)]
    pub format: Format,
    /// Input may alternatively be supplied through stdin
    pub file: Option<PathBuf>,
}

#[derive(Args)]
pub struct DecryptArgs {
    #[arg(long, short)]
    pub format: Format,
}

#[derive(Clone, ValueEnum)]
pub enum Format {
    Yaml,
    Json,
}
