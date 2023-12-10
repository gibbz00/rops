pub use file_format::*;
mod file_format {

    #[cfg(feature = "yaml")]
    pub use yaml::*;
    #[cfg(feature = "yaml")]
    mod yaml {

        #[cfg(feature = "test-utils")]
        pub use test_utils::{MockYamlTestUtil, YamlTestUtils};
        #[cfg(feature = "test-utils")]
        mod test_utils {
            use std::fmt::Debug;

            use serde::{de::DeserializeOwned, Serialize};

            use crate::*;

            pub trait MockYamlTestUtil {
                fn mock_yaml() -> String;
            }

            pub struct YamlTestUtils;

            impl YamlTestUtils {
                pub fn assert_serialization<T: MockTestUtil + MockYamlTestUtil + Serialize>() {
                    assert_eq!(T::mock_yaml(), serde_yaml::to_string(&T::mock()).unwrap())
                }

                pub fn assert_deserialization<T: MockTestUtil + MockYamlTestUtil + DeserializeOwned + Debug + PartialEq>() {
                    assert_eq!(T::mock(), serde_yaml::from_str(&T::mock_yaml()).unwrap())
                }
            }
        }
    }
}

pub use metadata::*;
mod metadata {
    pub use core::SopsFileMetadata;
    mod core {
        use serde::{Deserialize, Serialize};

        use crate::*;

        #[derive(Serialize, Deserialize)]
        pub struct SopsFileMetadata {
            #[cfg(feature = "age")]
            pub age: Vec<SopsFileAgeMetadata>,
        }
    }

    #[cfg(feature = "age")]
    pub use age::SopsFileAgeMetadata;
    #[cfg(feature = "age")]
    mod age {
        use serde::{Deserialize, Serialize};
        use serde_with::{serde_as, DisplayFromStr};

        use crate::*;

        #[serde_as]
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        pub struct SopsFileAgeMetadata {
            #[serde_as(as = "DisplayFromStr")]
            #[serde(rename = "recipient")]
            pub public_key: <AgeIntegration as Integration>::PublicKey,
            #[serde(rename = "enc")]
            pub encrypted_data_key: String,
        }

        #[cfg(feature = "test-utils")]
        mod mock {
            use super::*;

            impl MockTestUtil for SopsFileAgeMetadata {
                fn mock() -> Self {
                    Self {
                        public_key: AgeIntegration::mock_public_key(),
                        encrypted_data_key: AgeIntegration::mock_encrypted_data_key_str().to_string(),
                    }
                }
            }

            #[cfg(feature = "yaml")]
            impl MockYamlTestUtil for SopsFileAgeMetadata {
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
                    YamlTestUtils::assert_serialization::<SopsFileAgeMetadata>()
                }

                #[test]
                fn deserializes_yaml_age_sops_file_metadata() {
                    YamlTestUtils::assert_deserialization::<SopsFileAgeMetadata>()
                }
            }
        }
    }
}
