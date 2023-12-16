use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "F: FileFormat")]
pub struct RopsFile<S: RopsFileState, F: FileFormat> {
    #[serde(flatten)]
    pub map: RopsFileMap<S, F>,
    #[serde(rename = "sops")]
    pub metadata: RopsFileAgeMetadata,
    #[serde(skip)]
    state_marker: PhantomData<S>,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<S: RopsFileState, F: FileFormat> MockTestUtil for RopsFile<S, F>
    where
        RopsFileMap<S, F>: MockTestUtil,
    {
        fn mock() -> Self {
            Self {
                map: MockTestUtil::mock(),
                metadata: MockTestUtil::mock(),
                state_marker: PhantomData,
            }
        }
    }

    #[cfg(feature = "yaml")]
    mod yaml {
        use super::*;

        impl<S: RopsFileState> MockFileFormatUtil<YamlFileFormat> for RopsFile<S, YamlFileFormat>
        where
            RopsFileMap<S, YamlFileFormat>: MockFileFormatUtil<YamlFileFormat>,
        {
            fn mock_format_display() -> String {
                indoc::formatdoc! {"
                    {}
                    sops:
                    {}",
                    RopsFileMap::mock_format_display(),
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

        #[cfg(feature = "aes-gcm")]
        mod aes_gcm {
            use super::*;

            #[test]
            fn serializes_encrypted_rops_file() {
                FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFile<Encrypted<AES256GCM>, YamlFileFormat>>()
            }

            #[test]
            fn deserializes_encrypted_rops_file() {
                FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFile<Encrypted<AES256GCM>, YamlFileFormat>>()
            }
        }
    }
}
