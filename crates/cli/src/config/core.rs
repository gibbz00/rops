use std::path::Path;

use serde::Deserialize;

use crate::*;

#[derive(Default, Deserialize)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize))]
pub struct Config {
    pub creation_rules: Vec<CreationRule>,
}

impl Config {
    pub fn retrieve(optional_config_path: Option<&Path>) -> anyhow::Result<Self> {
        super::retrieve::retrieve_impl::<Self>(optional_config_path)
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use rops::test_utils::*;

    use super::*;

    impl MockTestUtil for Config {
        fn mock() -> Self {
            Self {
                creation_rules: vec![MockTestUtil::mock()],
            }
        }
    }

    impl MockOtherTestUtil for Config {
        fn mock_other() -> Self {
            Self {
                creation_rules: vec![MockOtherTestUtil::mock_other()],
            }
        }
    }
}
