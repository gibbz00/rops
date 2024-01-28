use std::path::Path;

use serde::Deserialize;

use crate::*;

#[derive(Default, Deserialize)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize))]
pub struct Config {
    pub creation_rules: Vec<CreationRule>,
}

impl Config {
    /// Order of retrieval:
    /// 1. Provided file path
    /// 2. By provided file path in environment variable (`$ROPS_CONFIG`)
    /// 3. File matching name `.rops.toml` in current dir or any ancestor thereof.
    /// 4. Fallback to default if none were found.
    pub fn retrieve(optional_config_path: Option<&Path>) -> anyhow::Result<Self> {
        super::retrieve::retrieve_impl::<Self>(optional_config_path)
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use rops::*;

    use super::*;

    impl MockOtherTestUtil for Config {
        fn mock_other() -> Self {
            Self {
                creation_rules: vec![MockOtherTestUtil::mock_other()],
            }
        }
    }
}
