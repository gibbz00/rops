use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Serialize, Deserialize)]
#[impl_tools::autoimpl(Debug, PartialEq)]
pub struct IntegrationMetadataUnit<I: Integration> {
    #[serde(flatten)]
    pub config: I::Config,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<IntegrationCreatedAt>,
    #[serde(rename = "enc")]
    pub encrypted_data_key: String,
}

impl<I: Integration> IntegrationMetadataUnit<I> {
    pub fn new(config: I::Config, data_key: &DataKey) -> IntegrationResult<Self> {
        Ok(Self {
            created_at: <I::Config as IntegrationConfig<I>>::INCLUDE_DATA_KEY_CREATED_AT.then_some(IntegrationCreatedAt::now()),
            encrypted_data_key: I::encrypt_data_key(config.key_id(), data_key)?,
            config,
        })
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<I: IntegrationTestUtils> MockTestUtil for IntegrationMetadataUnit<I>
    where
        I::Config: MockTestUtil,
    {
        fn mock() -> Self {
            Self {
                config: I::Config::mock(),
                encrypted_data_key: I::mock_encrypted_data_key_str().to_string(),
                created_at: <I::Config as IntegrationConfig<I>>::INCLUDE_DATA_KEY_CREATED_AT.then_some(IntegrationCreatedAt::mock()),
            }
        }
    }
}
