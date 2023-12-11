use serde::{Deserialize, Serialize};

use crate::*;

// TODO: either use typestate or newtype for plaintext and encrypted file differentiation.

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RopsFile<F: FileFormat> {
    #[serde(flatten)]
    pub map: F::Map,
    #[serde(rename = "sops")]
    pub metadata: RopsFileAgeMetadata,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<F: FileFormat> MockTestUtil for RopsFile<F>
    where
        F::Map: MockTestUtil,
    {
        fn mock() -> Self {
            Self {
                map: F::Map::mock(),
                metadata: MockTestUtil::mock(),
            }
        }
    }

    #[cfg(feature = "yaml")]
    mod yaml {
        use super::*;

        impl MockFileFormatUtil<YamlFileFormat> for RopsFile<YamlFileFormat> {
            fn mock_format_display() -> String {
                indoc::formatdoc! {"
                    {}
                    sops:
                    {}",
                    <YamlFileFormat as FileFormat>::Map::mock_format_display(),
                    textwrap::indent(&RopsFileAgeMetadata::mock_format_display(),"  ")
                }
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
        fn serializes_rops_file() {
            // TEMP:
            println!("{}", RopsFile::<YamlFileFormat>::mock_format_display());
            println!("{}", serde_yaml::to_string(&RopsFile::<YamlFileFormat>::mock()).unwrap());

            FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFile<YamlFileFormat>>()
        }

        #[test]
        fn deserializes_rops_file() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFile<YamlFileFormat>>()
        }
    }
}
