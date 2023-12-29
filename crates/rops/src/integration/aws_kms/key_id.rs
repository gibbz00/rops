use std::str::FromStr;

use derive_more::Display;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

use crate::*;

#[serde_as]
#[derive(Debug, PartialEq, Display, Serialize, Deserialize)]
#[display(fmt = "{}.{}", profile, key_arn)]
pub struct AwsKeyId {
    #[serde(rename = "aws_profile")]
    pub(crate) profile: String,
    #[serde(rename = "arn")]
    #[serde_as(as = "DisplayFromStr")]
    pub(crate) key_arn: AwsKeyResourceName,
}

impl FromStr for AwsKeyId {
    type Err = IntegrationError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        str.split_once('.')
            .ok_or(IntegrationError::KeyIdParsing(anyhow::anyhow!(
                "expected key id string to be delimited by a period following the syntax: 'profile.aws_key_arn', got '{}'",
                str
            )))
            .and_then(|(profile_str, key_arn_str)| {
                Ok(Self {
                    profile: profile_str.to_string(),
                    key_arn: key_arn_str.parse()?,
                })
            })
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    const MOCK_PROFILE_STR: &str = "default";

    impl MockTestUtil for AwsKeyId {
        fn mock() -> Self {
            Self {
                profile: MOCK_PROFILE_STR.to_string(),
                key_arn: MockTestUtil::mock(),
            }
        }
    }

    impl MockDisplayTestUtil for AwsKeyId {
        fn mock_display() -> String {
            format!("{}.{}", MOCK_PROFILE_STR, AwsKeyResourceName::mock_display())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_id() {
        FromStrTestUtils::assert_parse::<AwsKeyId>()
    }

    #[test]
    fn displays_key_id() {
        DisplayTestUtils::assert_display::<AwsKeyId>()
    }
}
