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

mod input_args;
pub use input_args::InputArgs;

mod misc_args;
pub use misc_args::{Format, PartialEncryptionArgs};

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
