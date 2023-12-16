use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

use crate::*;

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RopsFileAgeMetadata {
    #[serde_as(as = "DisplayFromStr")]
    #[serde(rename = "recipient")]
    pub public_key: <AgeIntegration as Integration>::PublicKey,
    #[serde(rename = "enc")]
    pub encrypted_data_key: String,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for RopsFileAgeMetadata {
        fn mock() -> Self {
            Self {
                public_key: AgeIntegration::mock_public_key(),
                encrypted_data_key: AgeIntegration::mock_encrypted_data_key_str().to_string(),
            }
        }
    }

    #[cfg(feature = "yaml")]
    impl MockFileFormatUtil<YamlFileFormat> for RopsFileAgeMetadata {
        fn mock_format_display() -> String {
            indoc::formatdoc! {"
                recipient: {}
                enc: |
                {}",
                AgeIntegration::mock_public_key_str(),
                textwrap::indent(AgeIntegration::mock_encrypted_data_key_str(),"  ")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "yaml")]
    mod yaml {
        use crate::*;

        #[test]
        fn serializes_rops_file_age_metadata() {
            FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFileAgeMetadata>()
        }

        #[test]
        fn deserializes_rops_file_age_metadata() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFileAgeMetadata>()
        }
    }
}
