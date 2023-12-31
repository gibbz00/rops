use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AwsKmsConfig {
    #[serde(flatten)]
    pub key_id: AwsKeyId,
}

impl IntegrationConfig<AwsKmsIntegration> for AwsKmsConfig {
    const INCLUDE_DATA_KEY_CREATED_AT: bool = true;

    fn new(key_id: <AwsKmsIntegration as Integration>::KeyId) -> Self {
        Self { key_id }
    }

    fn key_id(&self) -> &<AwsKmsIntegration as Integration>::KeyId {
        &self.key_id
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for AwsKmsConfig {
        fn mock() -> Self {
            Self {
                key_id: MockTestUtil::mock(),
            }
        }
    }
}
