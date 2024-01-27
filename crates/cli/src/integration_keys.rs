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
pub struct IntegrationKeys {
    /// Space separated list of public age keys
    #[arg(long = "age", display_order = 5)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub age: Vec<<AgeIntegration as Integration>::KeyId>,
    /// Space separated list of AWS KMS rops key id strings
    #[arg(long = "aws-kms", display_order = 5)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub aws_kms: Vec<<AwsKmsIntegration as Integration>::KeyId>,
}

impl IntegrationKeys {
    pub fn merge(&mut self, mut other: Self) {
        self.age.append(&mut other.age);
        self.aws_kms.append(&mut other.aws_kms);
    }
}
