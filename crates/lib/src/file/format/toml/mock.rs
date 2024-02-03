mod rops_file {
    use std::{fmt::Display, str::FromStr};

    use crate::*;

    impl<S: RopsFileState> MockFileFormatUtil<TomlFileFormat> for RopsFile<S, TomlFileFormat>
    where
        RopsFileFormatMap<S::MapState, TomlFileFormat>: MockFileFormatUtil<TomlFileFormat>,
        RopsFileMetadata<S::MetadataState>: MockFileFormatUtil<TomlFileFormat>,
        <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
    {
        fn mock_format_display() -> String {
            let metadata_table = RopsFileMetadata::mock_format_display().replace("[[", "[[sops.");

            indoc::formatdoc! {"
                {}
                [sops]
                {}",
                RopsFileFormatMap::mock_format_display(),
                metadata_table,
            }
        }
    }
}

mod map {
    use crate::*;

    impl MockFileFormatUtil<TomlFileFormat> for RopsFileFormatMap<DecryptedMap, TomlFileFormat> {
        fn mock_format_display() -> String {
            indoc::indoc! {"
                hello = \"world!\"
                booleans = [
                    true,
                    false,
                ]
                escape_unencrypted = \"plaintext\"

                [nested_map]
                null_key = \"null\"
                array = [
                    \"string\",
                    { nested_map_in_array = { integer = 1234 } },
                    { float = 1234.56789 },
                ]
            "}
            .to_string()
        }
    }

    #[cfg(feature = "aes-gcm")]
    impl MockFileFormatUtil<TomlFileFormat> for RopsFileFormatMap<EncryptedMap<AES256GCM>, TomlFileFormat> {
        fn mock_format_display() -> String {
            indoc::indoc! {"
                hello = \"ENC[AES256_GCM,data:3S1E9am/,iv:WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=,tag:nQUDkuh0OR1cjR5hGC5jOw==,type:str]\"
                booleans = [
                    \"ENC[AES256_GCM,data:bCdz2A==,iv:8kD+h1jClyVHBj9o2WZuAkjk+uD6A2lgNpcGljpQEhk=,tag:u3/fktl5HfFrVLERVvLRGw==,type:bool]\",
                    \"ENC[AES256_GCM,data:SgBh7wY=,iv:0s9Q9pQWbsZm2yHsmFalCzX0IqNb6ZqeY6QQYCWc+qU=,tag:OZb76BWCKbDLbcil4c8fYA==,type:bool]\",
                ]
                escape_unencrypted = \"plaintext\"

                [nested_map]
                null_key = \"null\"
                array = [
                    \"ENC[AES256_GCM,data:ANbeNrGp,iv:PRWGCPdOttPr5dlzT9te7WWCZ90J7+CvfY1vp60aADM=,tag:PvSLx4pLT5zRKOU0df8Xlg==,type:str]\",
                    { nested_map_in_array = { integer = \"ENC[AES256_GCM,data:qTW5qw==,iv:ugMxvR8YPwDgn2MbBpDX0lpCqzJY3GerhbA5jEKUbwE=,tag:d8utfA76C4XPzJyDfgE4Pw==,type:int]\" } },
                    { float = \"ENC[AES256_GCM,data:/MTg0fCennyN8g==,iv:+/8+Ljm+cls7BbDYZnlg6NVFkrkw4GkEfWU2aGW57qE=,tag:26uMp2JmVAckySIaL2BLCg==,type:float]\" },
                ]
            "}
            .to_string()
        }
    }
}

mod metadata {
    mod core {
        use std::{fmt::Display, str::FromStr};

        use crate::*;

        impl<S: RopsMetadataState> MockFileFormatUtil<TomlFileFormat> for RopsFileMetadata<S>
        where
            S::Mac: MockDisplayTestUtil,
            <S::Mac as FromStr>::Err: Display,
        {
            fn mock_format_display() -> String {
                let mut metadata_string = String::default();

                metadata_string.push_str(&indoc::formatdoc! {"
                    lastmodified = \"{}\"
                    mac = \"{}\"
                    unencrypted_suffix = \"{}\"

                    ",
                    LastModifiedDateTime::mock_display(),
                    S::Mac::mock_display(),
                    PartialEncryptionConfig::mock_display()
                });

                #[cfg(feature = "aws-kms")]
                metadata_string.push_str(&display_integration_metadata_unit::<AwsKmsIntegration>("kms"));

                #[cfg(feature = "age")]
                metadata_string.push_str(&display_integration_metadata_unit::<AgeIntegration>(AgeIntegration::NAME));

                metadata_string.pop();

                return metadata_string;

                fn display_integration_metadata_unit<I: IntegrationTestUtils>(metadata_field_name: &str) -> String
                where
                    IntegrationMetadataUnit<I>: MockFileFormatUtil<TomlFileFormat>,
                {
                    indoc::formatdoc!(
                        "
                        [[{}]]
                        {}
                        ",
                        metadata_field_name,
                        IntegrationMetadataUnit::<I>::mock_format_display()
                    )
                }
            }
        }

        impl<I: IntegrationTestUtils> MockFileFormatUtil<TomlFileFormat> for IntegrationMetadataUnit<I>
        where
            I::Config: MockFileFormatUtil<TomlFileFormat>,
        {
            fn mock_format_display() -> String {
                let mut config = I::Config::mock_format_display();
                config.pop();

                let config_display = match <I::Config as IntegrationConfig<I>>::INCLUDE_DATA_KEY_CREATED_AT {
                    true => indoc::formatdoc! {"
                        {}
                        created_at = \"{}\"",
                        config, IntegrationCreatedAt::mock_display()
                    },
                    false => config.to_string(),
                };

                let encrypted_data_key_str = I::mock_encrypted_data_key_str();

                match encrypted_data_key_str.contains('\n') {
                    true => indoc::formatdoc! {"
                        {}
                        enc = \"\"\"
                        {}\"\"\"
                        ",
                        &config_display, encrypted_data_key_str
                    },
                    false => indoc::formatdoc! {"
                        {}
                        enc = \"{}\"
                        ",
                        &config_display, encrypted_data_key_str
                    },
                }
            }
        }
    }

    mod integration_configs {
        use crate::*;

        #[cfg(feature = "age")]
        impl MockFileFormatUtil<TomlFileFormat> for AgeConfig {
            fn mock_format_display() -> String {
                format!("recipient = \"{}\"\n", <AgeIntegration as Integration>::KeyId::mock_display())
            }
        }

        #[cfg(feature = "aws-kms")]
        impl MockFileFormatUtil<TomlFileFormat> for AwsKmsConfig {
            fn mock_format_display() -> String {
                let AwsKeyId { profile, key_arn } = AwsKeyId::mock();
                indoc::formatdoc! {"
                    aws_profile = \"{}\"
                    arn = \"{}\"
                    ",
                    profile, key_arn
                }
            }
        }
    }
}
