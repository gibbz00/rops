use regex::Regex;
use rops::*;
use serde::Deserialize;

use crate::*;

#[derive(Deserialize)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize))]
pub struct CreationRule {
    #[serde(with = "serde_regex")]
    pub path_regex: Regex,
    #[cfg_attr(feature = "test-utils", serde(skip_serializing_if = "Option::is_none"))]
    pub mac_only_encrypted: Option<bool>,
    #[cfg_attr(feature = "test-utils", serde(skip_serializing_if = "Option::is_none"))]
    pub partial_encryption: Option<PartialEncryptionConfig>,
    pub integration_keys: IntegrationKeys,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for CreationRule {
        fn mock() -> Self {
            let file_to_match = InputArgs::mock().file.unwrap();

            Self {
                path_regex: file_to_match.to_str().unwrap().parse().unwrap(),
                integration_keys: MockTestUtil::mock(),
                mac_only_encrypted: Some(true),
                partial_encryption: Some(MockTestUtil::mock()),
            }
        }
    }

    impl MockOtherTestUtil for CreationRule {
        fn mock_other() -> Self {
            Self {
                path_regex: ".*".parse().unwrap(),
                integration_keys: MockOtherTestUtil::mock_other(),
                mac_only_encrypted: None,
                partial_encryption: None,
            }
        }
    }
}
