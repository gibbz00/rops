use regex::Regex;
use rops::file::metadata::{state::*, *};
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

impl CreationRule {
    pub fn implies_metadata(&self, metadata: &RopsFileMetadata<EncryptedMetadata<DefaultCipher, DefaultHasher>>) -> bool {
        self.mac_only_encrypted == metadata.mac_only_encrypted
            && self.partial_encryption == metadata.partial_encryption
            && self.integration_keys.implies_integration_metadata(&metadata.intregation)
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use rops::test_utils::*;

    use super::*;

    impl MockTestUtil for CreationRule {
        fn mock() -> Self {
            let file_to_match = InputArgs::mock().file.unwrap();
            let rops_file_metadata = RopsFileMetadata::<EncryptedMetadata<DefaultCipher, DefaultHasher>>::mock();

            Self {
                path_regex: file_to_match.to_str().unwrap().parse().unwrap(),
                integration_keys: MockTestUtil::mock(),
                mac_only_encrypted: rops_file_metadata.mac_only_encrypted,
                partial_encryption: rops_file_metadata.partial_encryption,
            }
        }
    }

    impl MockOtherTestUtil for CreationRule {
        fn mock_other() -> Self {
            Self {
                path_regex: ".*".parse().unwrap(),
                integration_keys: MockOtherTestUtil::mock_other(),
                mac_only_encrypted: Some(true),
                partial_encryption: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rops::test_utils::*;

    use super::*;

    #[test]
    fn implies_metadata() {
        assert!(CreationRule::mock().implies_metadata(&MockTestUtil::mock()));
        assert!(!CreationRule::mock_other().implies_metadata(&MockTestUtil::mock()));
    }
}
