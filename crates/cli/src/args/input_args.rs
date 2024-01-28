use std::path::{Path, PathBuf};

use clap::{Args, ValueHint};

use crate::*;

#[derive(Args)]
pub struct InputArgs {
    /// Read config from provided path
    #[arg(long, short, display_order = 0, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Required if no file argument is found to infer by extension
    #[arg(long, short, display_order = 20)]
    pub format: Option<Format>,
    /// Input may alternatively be supplied through stdin
    #[arg(value_hint = ValueHint::FilePath)]
    pub file: Option<PathBuf>,
}

impl ConfigArg for InputArgs {
    fn config_path(&self) -> Option<&Path> {
        self.config.as_deref()
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use rops::*;

    use super::*;

    impl MockTestUtil for InputArgs {
        fn mock() -> Self {
            Self {
                config: None,
                format: None,
                file: Some("rops_file.toml".into()),
            }
        }
    }
}
