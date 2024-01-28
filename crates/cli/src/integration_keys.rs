use clap::Args;
use indexmap::IndexSet;
use rops::*;
use serde::Deserialize;
use serde_with::DisplayFromStr;

/*
    - Attribute doc comments are for clap parsing.
    - Serde proc macros are for use in config serialization.
*/
#[serde_with::serde_as]
#[derive(Default, Args, Deserialize)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize))]
pub struct IntegrationKeys {
    /// Space separated list of public age keys
    #[arg(long = "age", display_order = 5)]
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    #[cfg_attr(feature = "test-utils", serde(skip_serializing_if = "Vec::is_empty"))]
    pub age: Vec<<AgeIntegration as Integration>::KeyId>,
    /// Space separated list of AWS KMS rops key id strings
    #[arg(long = "aws-kms", display_order = 5)]
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    #[cfg_attr(feature = "test-utils", serde(skip_serializing_if = "Vec::is_empty"))]
    pub aws_kms: Vec<<AwsKmsIntegration as Integration>::KeyId>,
}

impl IntegrationKeys {
    pub fn merge(&mut self, mut other: Self) {
        self.age.append(&mut other.age);
        self.aws_kms.append(&mut other.aws_kms);
    }

    pub fn implies_integration_metadata(&self, integration_metadata: &IntegrationMetadata) -> bool {
        return identical_keys::<AgeIntegration>(&self.age, &integration_metadata.age)
            && identical_keys::<AwsKmsIntegration>(&self.aws_kms, &integration_metadata.kms);

        fn identical_keys<I: Integration>(arg_keys: &[I::KeyId], metadata_keys: &IntegrationMetadataUnits<I>) -> bool {
            let args_keys_set = IndexSet::<&I::KeyId>::from_iter(arg_keys.iter());
            let metadata_keys_set = IndexSet::<&I::KeyId>::from_iter(metadata_keys.keys());
            args_keys_set.symmetric_difference(&metadata_keys_set).next().is_none()
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for IntegrationKeys {
        fn mock() -> Self {
            Self {
                age: vec![<<AgeIntegration as Integration>::KeyId>::mock()],
                aws_kms: vec![<<AwsKmsIntegration as Integration>::KeyId>::mock()],
            }
        }
    }

    impl MockOtherTestUtil for IntegrationKeys {
        fn mock_other() -> Self {
            Self {
                age: vec![<<AgeIntegration as Integration>::KeyId>::mock_other()],
                aws_kms: vec![],
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implies_metadata() {
        assert!(IntegrationKeys::mock().implies_integration_metadata(&IntegrationMetadata::mock()));
        assert!(!IntegrationKeys::mock_other().implies_integration_metadata(&IntegrationMetadata::mock()));
    }
}
