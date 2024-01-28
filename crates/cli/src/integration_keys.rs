use clap::Args;
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
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for IntegrationKeys {
        fn mock() -> Self {
            Self {
                age: vec![<<AgeIntegration as Integration>::KeyId>::mock()],
                aws_kms: vec![],
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
