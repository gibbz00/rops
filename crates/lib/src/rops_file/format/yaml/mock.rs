mod rops_file {
    use std::{fmt::Display, str::FromStr};

    use crate::*;

    impl<S: RopsFileState> MockFileFormatUtil<YamlFileFormat> for RopsFile<S, YamlFileFormat>
    where
        RopsFileFormatMap<S::MapState, YamlFileFormat>: MockFileFormatUtil<YamlFileFormat>,
        RopsFileMetadata<S::MetadataState>: MockFileFormatUtil<YamlFileFormat>,
        <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
    {
        fn mock_format_display() -> String {
            indoc::formatdoc! {"
                    {}
                    sops:
                    {}",
                RopsFileFormatMap::mock_format_display(),
                textwrap::indent(&RopsFileMetadata::mock_format_display(),"  ")
            }
        }
    }
}

mod map {
    use crate::*;

    impl MockFileFormatUtil<YamlFileFormat> for RopsFileFormatMap<DecryptedMap, YamlFileFormat> {
        fn mock_format_display() -> String {
            indoc::indoc! {"
                    hello: world!
                    nested_map:
                      null_key: null
                      array:
                      - string
                      - nested_map_in_array:
                          integer: 1234
                      - float: 1234.56789
                    booleans:
                    - true
                    - false"
            }
            .to_string()
        }
    }

    #[cfg(feature = "aes-gcm")]
    impl MockFileFormatUtil<YamlFileFormat> for RopsFileFormatMap<EncryptedMap<AES256GCM>, YamlFileFormat> {
        fn mock_format_display() -> String {
            indoc::indoc! {"
                    hello: ENC[AES256_GCM,data:3S1E9am/,iv:WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=,tag:nQUDkuh0OR1cjR5hGC5jOw==,type:str]
                    nested_map:
                      null_key: null
                      array:
                      - ENC[AES256_GCM,data:ANbeNrGp,iv:PRWGCPdOttPr5dlzT9te7WWCZ90J7+CvfY1vp60aADM=,tag:PvSLx4pLT5zRKOU0df8Xlg==,type:str]
                      - nested_map_in_array:
                          integer: ENC[AES256_GCM,data:qTW5qw==,iv:ugMxvR8YPwDgn2MbBpDX0lpCqzJY3GerhbA5jEKUbwE=,tag:d8utfA76C4XPzJyDfgE4Pw==,type:int]
                      - float: ENC[AES256_GCM,data:/MTg0fCennyN8g==,iv:+/8+Ljm+cls7BbDYZnlg6NVFkrkw4GkEfWU2aGW57qE=,tag:26uMp2JmVAckySIaL2BLCg==,type:float]
                    booleans:
                    - ENC[AES256_GCM,data:bCdz2A==,iv:8kD+h1jClyVHBj9o2WZuAkjk+uD6A2lgNpcGljpQEhk=,tag:u3/fktl5HfFrVLERVvLRGw==,type:bool]
                    - ENC[AES256_GCM,data:SgBh7wY=,iv:0s9Q9pQWbsZm2yHsmFalCzX0IqNb6ZqeY6QQYCWc+qU=,tag:OZb76BWCKbDLbcil4c8fYA==,type:bool]"
            }
            .to_string()
        }
    }

    impl<S: RopsMapState> MockTestUtil for RopsFileFormatMap<S, YamlFileFormat>
    where
        Self: MockFileFormatUtil<YamlFileFormat>,
    {
        fn mock() -> Self {
            serde_yaml::from_str(&Self::mock_format_display()).expect("mock yaml string not serializable")
        }
    }
}

mod metadata {
    mod core {
        use std::{fmt::Display, str::FromStr};

        use crate::*;

        impl<S: RopsMetadataState> MockFileFormatUtil<YamlFileFormat> for RopsFileMetadata<S>
        where
            S::Mac: MockDisplayTestUtil,
            <S::Mac as FromStr>::Err: Display,
        {
            fn mock_format_display() -> String {
                let mut metadata_string = String::new();

                #[cfg(feature = "age")]
                {
                    let age_metadata_yaml_string = RopsFileAgeMetadata::mock_format_display();
                    let (first_line, remaining_lines) = age_metadata_yaml_string
                        .split_once('\n')
                        .expect("no newline delimeter in yaml age metadata");
                    metadata_string.push_str(&indoc::formatdoc! {"
                            age:
                            - {}
                            {}",
                        first_line,
                        textwrap::indent(remaining_lines, "  ")
                    });
                }

                metadata_string.push_str(&format!("lastmodified: {}\n", LastModifiedDateTime::mock_display()));
                metadata_string.push_str(&format!("mac: {}\n", S::Mac::mock_display()));

                metadata_string
            }
        }
    }

    #[cfg(feature = "age")]
    mod age {
        use crate::*;

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
}
