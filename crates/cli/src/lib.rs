mod error;
pub use error::RopsCliError;

mod args;
pub use args::*;

mod run;
pub use run::run;

pub use cryptography_stack::{DefaultCipher, DefaultHasher};
mod cryptography_stack {
    use rops::{AES256GCM, SHA512};

    pub type DefaultCipher = AES256GCM;
    pub type DefaultHasher = SHA512;
}
