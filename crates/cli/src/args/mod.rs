mod core;
pub use core::{CliArgs, CliSubcommand};

mod encrypt;
pub use encrypt::EncryptArgs;

mod decrypt;
pub use decrypt::DecryptArgs;

mod edit;
pub use edit::EditArgs;

mod keys;
pub use keys::{KeyInputArgs, KeysSubcommand};

mod common;
pub use common::{Format, InputArgs, PartialEncryptionArgs};

mod merge_config;
pub use merge_config::{ConfigArg, MergeConfig};

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn verify_args() {
        CliArgs::command().debug_assert()
    }
}
