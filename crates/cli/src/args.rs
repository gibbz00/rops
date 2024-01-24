use clap::{Parser, Subcommand};

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
    Edit(InputArgs),
    /// Encrypted rops file key management.
    #[command(subcommand, visible_alias = "k")]
    Keys(KeysSubcommand),
}

mod encrypt;
pub use encrypt::EncryptArgs;

mod decrypt;
pub use decrypt::DecryptArgs;

mod keys;
pub use keys::{KeyInputArgs, KeysSubcommand};

mod common;
pub use common::{Format, InputArgs, IntegrationKeys, PartialEncryptionArgs};

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn verify_args() {
        CliArgs::command().debug_assert()
    }
}
