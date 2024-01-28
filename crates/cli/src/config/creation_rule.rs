use regex::Regex;
use serde::Deserialize;

use crate::*;

#[derive(Deserialize)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize))]
pub struct CreationRule {
    #[serde(with = "serde_regex")]
    pub path_regex: Regex,
    pub integration_keys: IntegrationKeys,
}

#[cfg(feature = "test-utils")]
mod mock {
    use rops::*;

    use super::*;

    impl MockOtherTestUtil for CreationRule {
        fn mock_other() -> Self {
            Self {
                path_regex: ".*".parse().unwrap(),
                integration_keys: MockOtherTestUtil::mock_other(),
            }
        }
    }
}
