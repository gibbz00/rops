use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RopsFile<S: RopsFileState, F: FileFormat> {
    #[serde(flatten)]
    pub map: F::Map,
    #[serde(rename = "sops")]
    pub metadata: RopsFileAgeMetadata,
    #[serde(skip)]
    state_marker: PhantomData<S>,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<F: FileFormat> MockTestUtil for RopsFile<Decrypted, F>
    where
        F::Map: MockTestUtil,
    {
        fn mock() -> Self {
            Self {
                map: F::Map::mock(),
                metadata: MockTestUtil::mock(),
                state_marker: PhantomData,
            }
        }
    }

    #[cfg(feature = "yaml")]
    mod yaml {
        use super::*;

        impl MockFileFormatUtil<YamlFileFormat> for RopsFile<Decrypted, YamlFileFormat> {
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
        fn serializes_decrypted_rops_file() {
            FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFile<Decrypted, YamlFileFormat>>()
        }

        #[test]
        fn deserializes_decrypted_rops_file() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFile<Decrypted, YamlFileFormat>>()
        }
    }
}
