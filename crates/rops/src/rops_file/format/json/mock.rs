mod rops_file {
    use std::{fmt::Display, str::FromStr};

    use crate::*;

    impl<S: RopsFileState> MockFileFormatUtil<JsonFileFormat> for RopsFile<S, JsonFileFormat>
    where
        RopsFileFormatMap<S::MapState, JsonFileFormat>: MockFileFormatUtil<JsonFileFormat>,
        RopsFileMetadata<S::MetadataState>: MockFileFormatUtil<JsonFileFormat>,
        <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
    {
        fn mock_format_display() -> String {
            format! {"{{{},\"sops\":{}}}",
                RopsFileFormatMap::mock_format_display().strip_prefix('{').unwrap().strip_suffix('}').unwrap(),
                &RopsFileMetadata::mock_format_display(),
            }
        }
    }
}

mod map {
    use crate::*;

    impl MockFileFormatUtil<JsonFileFormat> for RopsFileFormatMap<DecryptedMap, JsonFileFormat> {
        fn mock_format_display() -> String {
            serde_json::json!({
                "hello": "world!",
                "nested_map": {
                    "null_key": null,
                    "array": [
                        "string",
                        {
                            "nested_map_in_array": {
                                "integer": 1234,
                            },
                        },
                        { "float": 1234.56789 },
                    ]
                },
                "booleans": [true, false],
                "escape_unencrypted": "plaintext"
            })
            .to_string()
        }
    }

    #[cfg(feature = "aes-gcm")]
    impl MockFileFormatUtil<JsonFileFormat> for RopsFileFormatMap<EncryptedMap<AES256GCM>, JsonFileFormat> {
        fn mock_format_display() -> String {
            serde_json::json!({
                "hello": "ENC[AES256_GCM,data:3S1E9am/,iv:WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=,tag:nQUDkuh0OR1cjR5hGC5jOw==,type:str]",
                "nested_map": {
                    "null_key": null,
                    "array": [
                        "ENC[AES256_GCM,data:ANbeNrGp,iv:PRWGCPdOttPr5dlzT9te7WWCZ90J7+CvfY1vp60aADM=,tag:PvSLx4pLT5zRKOU0df8Xlg==,type:str]",
                        {
                            "nested_map_in_array": {
                              "integer": "ENC[AES256_GCM,data:qTW5qw==,iv:ugMxvR8YPwDgn2MbBpDX0lpCqzJY3GerhbA5jEKUbwE=,tag:d8utfA76C4XPzJyDfgE4Pw==,type:int]"
                            }
                        },
                        { "float": "ENC[AES256_GCM,data:/MTg0fCennyN8g==,iv:+/8+Ljm+cls7BbDYZnlg6NVFkrkw4GkEfWU2aGW57qE=,tag:26uMp2JmVAckySIaL2BLCg==,type:float]" }
                    ]
                },
                "booleans": [
                    "ENC[AES256_GCM,data:bCdz2A==,iv:8kD+h1jClyVHBj9o2WZuAkjk+uD6A2lgNpcGljpQEhk=,tag:u3/fktl5HfFrVLERVvLRGw==,type:bool]",
                    "ENC[AES256_GCM,data:SgBh7wY=,iv:0s9Q9pQWbsZm2yHsmFalCzX0IqNb6ZqeY6QQYCWc+qU=,tag:OZb76BWCKbDLbcil4c8fYA==,type:bool]",
                ],
                "escape_unencrypted": "plaintext"
            }).to_string()
        }
    }
}

mod metadata {
    mod core {
        use std::{fmt::Display, str::FromStr};

        use crate::*;

        impl<S: RopsMetadataState> MockFileFormatUtil<JsonFileFormat> for RopsFileMetadata<S>
        where
            S::Mac: MockDisplayTestUtil,
            <S::Mac as FromStr>::Err: Display,
        {
            fn mock_format_display() -> String {
                let mut metadata_string = "{".to_string();

                #[cfg(feature = "age")]
                {
                    metadata_string.push_str(&display_integration_metadata_unit::<AgeIntegration>());
                }

                metadata_string.push_str(&format!(
                    "\"lastmodified\":\"{}\",\"mac\":\"{}\",\"unencrypted_suffix\":\"{}\"}}",
                    LastModifiedDateTime::mock_display(),
                    S::Mac::mock_display(),
                    PartialEncryptionConfig::mock_display()
                ));

                return metadata_string;

                fn display_integration_metadata_unit<I: IntegrationTestUtils>() -> String
                where
                    IntegrationMetadataUnit<I>: MockFileFormatUtil<JsonFileFormat>,
                    for<'a> &'a I::PublicKey: From<&'a I::Config>,
                {
                    format!("\"{}\":[{}],", I::NAME, IntegrationMetadataUnit::<I>::mock_format_display())
                }
            }
        }

        impl<I: IntegrationTestUtils> MockFileFormatUtil<JsonFileFormat> for IntegrationMetadataUnit<I>
        where
            I::Config: MockFileFormatUtil<JsonFileFormat>,
            for<'a> &'a I::PublicKey: From<&'a I::Config>,
        {
            fn mock_format_display() -> String {
                format! {"{{{},\"enc\":\"{}\"}}",
                    I::Config::mock_format_display().strip_prefix('{').unwrap().strip_suffix('}').unwrap(), I::mock_encrypted_data_key_str().replace('\n', "\\n")
                }
            }
        }
    }

    #[cfg(feature = "age")]
    mod age {
        use crate::*;

        impl MockFileFormatUtil<JsonFileFormat> for AgeConfig {
            fn mock_format_display() -> String {
                format!("{{\"recipient\":\"{}\"}}", AgeIntegration::mock_public_key_str())
            }
        }
    }
}
