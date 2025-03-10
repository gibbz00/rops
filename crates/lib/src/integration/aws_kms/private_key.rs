use std::str::FromStr;

use derive_more::Display;

use crate::*;

#[derive(Debug, PartialEq, Display)]
#[display("{}.{}.{}", profile, id, secret)]
pub struct AwsPrivateKey {
    pub(super) profile: String,
    pub(super) id: String,
    pub(super) secret: String,
}

impl FromStr for AwsPrivateKey {
    type Err = IntegrationError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        const PROFILE_COMPONENT: &str = "profile";
        const ID_COMPONENT: &str = "aws_access_key_id";
        const SECRET_COMPONENT: &str = "aws_secret_access_key";

        let mut key_components = str.split('.');

        let mut next_component = |component_name: &str| -> IntegrationResult<String> {
            key_components
                .next()
                .ok_or(IntegrationError::PrivateKeyParsing(anyhow::anyhow!(
                    "invalid private key syntax, missing the {} component in: '{}.{}.{}', got: '{}'",
                    component_name,
                    PROFILE_COMPONENT,
                    ID_COMPONENT,
                    SECRET_COMPONENT,
                    str
                )))
                .map(ToString::to_string)
        };

        // IMPROVEMENT: assert length of iterator is 3.

        Ok(Self {
            profile: next_component(PROFILE_COMPONENT)?,
            id: next_component(ID_COMPONENT)?,
            secret: next_component(SECRET_COMPONENT)?,
        })
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    // TODO(XXX): Access key to a rops dummy account with the singular permission of using the mock AWS
    // KMS key. Use #[ignore] and read secret from env with new account before release?

    impl MockDisplayTestUtil for AwsPrivateKey {
        fn mock_display() -> String {
            "default.AKIA3647SRLJ3HRB32X2.BRZLmZxLHH3A2OSBiUHHJ3iX7mI5Astd2ZDIkigu".to_string()
        }
    }

    impl MockTestUtil for AwsPrivateKey {
        fn mock() -> Self {
            Self {
                profile: "default".to_string(),
                id: "AKIA3647SRLJ3HRB32X2".to_string(),
                secret: "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".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_private_key() {
        FromStrTestUtils::assert_parse::<AwsPrivateKey>()
    }

    #[test]
    fn displays_private_key() {
        DisplayTestUtils::assert_display::<AwsPrivateKey>()
    }
}
