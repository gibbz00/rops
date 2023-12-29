use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct IntegrationMetadata {
    #[cfg(feature = "aws-kms")]
    // Naming inconsistency inherited from SOPS, should ideally be named `aws_kms`
    // (a serde(alias = "kms") could be kept to supporting migrations.)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub kms: Vec<IntegrationMetadataUnit<AwsKmsIntegration>>,
    #[cfg(feature = "age")]
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub age: Vec<IntegrationMetadataUnit<AgeIntegration>>,
}

impl IntegrationMetadata {
    pub fn find_data_key(&self) -> IntegrationResult<Option<DataKey>> {
        // In order of what is assumed to be quickest:

        #[cfg(feature = "age")]
        if let Some(decrypt_result) = self.age.iter().find_map(|age_metadata| {
            AgeIntegration::decrypt_data_key(&age_metadata.config.key_id, &age_metadata.encrypted_data_key).transpose()
        }) {
            return decrypt_result.map(Some);
        }

        #[cfg(feature = "aws-kms")]
        if let Some(decrypt_result) = self.kms.iter().find_map(|aws_kms_metadata| {
            AwsKmsIntegration::decrypt_data_key(&aws_kms_metadata.config.key_id, &aws_kms_metadata.encrypted_data_key).transpose()
        }) {
            return decrypt_result.map(Some);
        }

        Ok(None)
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for IntegrationMetadata {
        fn mock() -> Self {
            Self {
                #[cfg(feature = "aws-kms")]
                kms: vec![MockTestUtil::mock()],
                #[cfg(feature = "age")]
                age: vec![MockTestUtil::mock()],
            }
        }
    }
}
