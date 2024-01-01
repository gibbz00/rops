use std::{fmt::Display, str::FromStr};

use aws_arn::{AccountIdentifier, Identifier, ResourceIdentifier, ResourceName};
use aws_sdk_kms::config::Region;

use crate::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AwsKeyResourceName {
    pub optional_partition: Option<Identifier>,
    pub service: Identifier,
    pub region: Region,
    pub optional_account_id: Option<AccountIdentifier>,
    pub optional_key_id_parent_path: Option<ResourceIdentifier>,
    pub key_id: Identifier,
}

impl FromStr for AwsKeyResourceName {
    type Err = IntegrationError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        str.parse::<aws_arn::ResourceName>()
            .map_err(|err| IntegrationError::KeyIdParsing(err.into()))?
            .try_into()
    }
}

impl TryFrom<ResourceName> for AwsKeyResourceName {
    type Error = IntegrationError;

    fn try_from(arn: ResourceName) -> Result<Self, Self::Error> {
        let arn_clone = arn.clone();
        let create_error = |context: &str| -> IntegrationError {
            IntegrationError::KeyIdParsing(anyhow::anyhow!("{} in Amazon Resource Name (arn), got: {}", context, arn_clone))
        };

        #[rustfmt::skip]
        let ResourceName { partition, service, region, account_id, resource } = arn;

        const INVALID_IDENTIFIER: &str = "unable to parse identifier from a split resource identifier";
        let (key_id_parent_path, key_id): (Option<ResourceIdentifier>, Identifier) = resource
            .rsplit_once('/')
            .map(|(parent_path_str, key_id_str)| {
                (
                    Some(parent_path_str.parse::<ResourceIdentifier>().expect(INVALID_IDENTIFIER)),
                    key_id_str.parse::<Identifier>().expect(INVALID_IDENTIFIER),
                )
            })
            .unwrap_or_else(|| (None, resource.parse().expect(INVALID_IDENTIFIER)));

        Ok(Self {
            optional_partition: partition,
            service,
            region: region
                .ok_or(create_error("missing region "))
                .map(|region_id| Region::new(region_id.to_string()))?,
            optional_account_id: account_id,
            optional_key_id_parent_path: key_id_parent_path,
            key_id,
        })
    }
}
impl Display for AwsKeyResourceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[rustfmt::skip]
        let Self { optional_partition, service, region, optional_account_id, optional_key_id_parent_path, key_id } = self;

        let mut display_string = String::from("arn:");

        push_optional_identifier(&mut display_string, optional_partition.as_deref());
        push_identifier(&mut display_string, service);
        push_identifier(&mut display_string, region.as_ref());
        push_optional_identifier(&mut display_string, optional_account_id.as_deref());

        optional_key_id_parent_path.iter().for_each(|parent_str| {
            display_string.push_str(parent_str);
            display_string.push('/')
        });

        display_string.push_str(key_id);

        return write!(f, "{}", display_string);

        fn push_identifier(display_string: &mut String, identifier: &str) {
            display_string.push_str(identifier);
            display_string.push(':');
        }

        fn push_optional_identifier(display_string: &mut String, optional_identifier: Option<&str>) {
            if let Some(identifier) = optional_identifier {
                push_identifier(display_string, identifier)
            }
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use std::fmt::Debug;

    use super::*;

    impl MockTestUtil for AwsKeyResourceName {
        fn mock() -> Self {
            return AwsKeyResourceName {
                optional_partition: Some(mock_helper("aws")),
                service: mock_helper("kms"),
                region: Region::from_static("eu-north-1"),
                optional_account_id: Some(mock_helper("822284028627")),
                optional_key_id_parent_path: Some(mock_helper("key")),
                key_id: mock_helper("a219f9b1-f371-466a-9143-7adff993aa05"),
            };

            fn mock_helper<T: FromStr>(identifier_str: &str) -> T
            where
                T::Err: Debug,
            {
                identifier_str.parse().unwrap()
            }
        }
    }

    impl MockDisplayTestUtil for AwsKeyResourceName {
        fn mock_display() -> String {
            "arn:aws:kms:eu-north-1:822284028627:key/a219f9b1-f371-466a-9143-7adff993aa05".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_arn() {
        FromStrTestUtils::assert_parse::<AwsKeyResourceName>()
    }

    #[test]
    fn displays_key_arn() {
        DisplayTestUtils::assert_display::<AwsKeyResourceName>()
    }
}
