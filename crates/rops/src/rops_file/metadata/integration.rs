use serde::{Deserialize, Serialize};

use crate::*;

pub use unit::IntegrationMetadataUnit;
mod unit {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct IntegrationMetadataUnit<I: Integration>
    where
        for<'a> &'a I::PublicKey: From<&'a I::Config>,
    {
        #[serde(flatten)]
        pub config: I::Config,
        #[serde(rename = "enc")]
        pub encrypted_data_key: String,
    }

    impl<I: Integration> IntegrationMetadataUnit<I>
    where
        for<'a> &'a I::PublicKey: From<&'a I::Config>,
    {
        pub fn new(config: I::Config, data_key: &DataKey) -> IntegrationResult<Self> {
            Ok(Self {
                encrypted_data_key: I::encrypt_data_key((&config).into(), data_key)?,
                config,
            })
        }
    }
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct IntegrationMetadata {
    #[cfg(feature = "age")]
    pub age: Vec<IntegrationMetadataUnit<AgeIntegration>>,
}

impl IntegrationMetadata {
    pub fn find_data_key(&self) -> IntegrationResult<Option<DataKey>> {
        // In order of what is assumed to be quickest:

        #[cfg(feature = "age")]
        if let Some(data_key) = self.data_key_from_age()? {
            return Ok(Some(data_key));
        }

        Ok(None)
    }

    #[cfg(feature = "age")]
    // pub(crate) to allow centralized integration testing, should otherwise be considered private
    pub(crate) fn data_key_from_age(&self) -> IntegrationResult<Option<DataKey>> {
        let private_keys = AgeIntegration::retrieve_private_keys()?;

        for age_metadata in &self.age {
            for private_key in &private_keys {
                if &private_key.to_public() == <&<AgeIntegration as Integration>::PublicKey>::from(&age_metadata.config) {
                    return AgeIntegration::decrypt_data_key(private_key, &age_metadata.encrypted_data_key).map(Some);
                }
            }
        }

        Ok(None)
    }
}

#[cfg(feature = "test-utils")]
mod mock {

    use super::*;

    impl<I: IntegrationTestUtils> MockTestUtil for IntegrationMetadataUnit<I>
    where
        I::Config: MockTestUtil,
        for<'a> &'a I::PublicKey: From<&'a I::Config>,
    {
        fn mock() -> Self {
            Self {
                config: I::Config::mock(),
                encrypted_data_key: I::mock_encrypted_data_key_str().to_string(),
            }
        }
    }

    impl MockTestUtil for IntegrationMetadata {
        fn mock() -> Self {
            Self {
                #[cfg(feature = "age")]
                age: vec![MockTestUtil::mock()],
            }
        }
    }
}
