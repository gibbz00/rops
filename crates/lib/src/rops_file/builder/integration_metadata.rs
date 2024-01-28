use std::{fmt::Debug, hash::Hash};

use crate::*;

#[derive(Default)]
pub struct IntegrationMetadataBuilder {
    #[cfg(feature = "age")]
    pub age_key_ids: Vec<<AgeIntegration as Integration>::KeyId>,
    #[cfg(feature = "aws-kms")]
    pub aws_kms_key_ids: Vec<<AwsKmsIntegration as Integration>::KeyId>,
}

impl IntegrationMetadataBuilder {
    pub fn into_integration_metadata(self, data_key: &DataKey) -> IntegrationResult<IntegrationMetadata> {
        let mut integration_metadata = IntegrationMetadata::default();

        #[cfg(feature = "age")]
        integration_metadata.add_keys::<AgeIntegration>(self.age_key_ids, data_key)?;
        #[cfg(feature = "aws-kms")]
        integration_metadata.add_keys::<AwsKmsIntegration>(self.aws_kms_key_ids, data_key)?;

        Ok(integration_metadata)
    }
}

pub trait AppendIntegrationKey<I: Integration>: Debug + PartialEq + Eq + Hash {
    fn append_to_metadata_builder(self, integration_metadata_builder: &mut IntegrationMetadataBuilder);
}
