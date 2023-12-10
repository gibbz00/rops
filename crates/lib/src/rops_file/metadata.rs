pub use core::RopsFileMetadata;
mod core {
    use serde::{Deserialize, Serialize};

    use crate::*;

    #[derive(Serialize, Deserialize)]
    pub struct RopsFileMetadata {
        #[cfg(feature = "age")]
        pub age: Vec<RopsFileAgeMetadata>,
    }
}

#[cfg(feature = "age")]
pub use age::RopsFileAgeMetadata;
#[cfg(feature = "age")]
mod age {
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
        impl MockYamlTestUtil for RopsFileAgeMetadata {
            fn mock_yaml() -> String {
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
            fn serializes_yaml_age_sops_file_metadata() {
                YamlTestUtils::assert_serialization::<RopsFileAgeMetadata>()
            }

            #[test]
            fn deserializes_yaml_age_sops_file_metadata() {
                YamlTestUtils::assert_deserialization::<RopsFileAgeMetadata>()
            }
        }
    }
}
