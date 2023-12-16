use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RopsFileMetadata {
    #[cfg(feature = "age")]
    pub age: Vec<RopsFileAgeMetadata>,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for RopsFileMetadata {
        fn mock() -> Self {
            Self {
                #[cfg(feature = "age")]
                age: vec![RopsFileAgeMetadata::mock()],
            }
        }
    }

    impl MockFileFormatUtil<YamlFileFormat> for RopsFileMetadata {
        fn mock_format_display() -> String {
            #[cfg(feature = "age")]
            {
                let age_metadata_yaml_string = RopsFileAgeMetadata::mock_format_display();
                let (first_line, remaining_lines) = age_metadata_yaml_string
                    .split_once('\n')
                    .expect("no newline delimeter in yaml age metadata");
                indoc::formatdoc! {"
                    age:
                    - {}
                    {}",
                    first_line,
                    textwrap::indent(remaining_lines, "  ")
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
        fn serializes_metadata() {
            FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFileMetadata>()
        }

        #[test]
        fn deserializes_metadata() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFileMetadata>()
        }
    }
}
