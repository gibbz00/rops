mod transforms {
    mod to_internal {
        mod encrypted {
            use crate::*;

            use super::helpers;

            #[cfg(feature = "aes-gcm")]
            mod aes_gcm {
                use super::*;

                #[test]
                fn transforms_encrypted_yaml_map() {
                    assert_eq!(
                        RopsMap::mock(),
                        RopsFileFormatMap::<EncryptedMap<AES256GCM>, YamlFileFormat>::mock()
                            .to_internal(None)
                            .unwrap()
                    )
                }

                #[test]
                fn mixes_partial_enryption() {
                    let escape_suffix = "escaped".to_string();
                    pretty_assertions::assert_eq!(
                        RopsMap(indexmap::indexmap! {
                            escape_suffix.clone() => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::String("something".to_string()))),
                            "encrypted".to_string() => RopsTree::Leaf(RopsMapEncryptedLeaf::Encrypted(EncryptedRopsValue::mock()))
                        }),
                        helpers::create_format_map::<EncryptedMap<AES256GCM>>(&indoc::formatdoc! {"
                        {}: something
                        encrypted: {}",
                            escape_suffix,
                            EncryptedRopsValue::<AES256GCM>::mock_display(),
                        })
                        .to_internal(Some(&PartialEncryptionConfig::UnencryptedSuffix("escaped".to_string())))
                        .unwrap()
                    )
                }
            }

            #[test]
            fn disallows_boolean_values_when_encrypted() {
                assert_allowed_value_helper("disallowed_boolean: true")
            }

            #[test]
            fn allows_boolean_values_when_escaped() {
                assert_allowed_value_helper("allowed_boolean: true")
            }

            #[test]
            fn disallows_integer_values_when_encrypted() {
                assert_allowed_value_helper("disallowed_integer: 1")
            }

            #[test]
            fn allows_integer_values_when_encrypted() {
                assert_allowed_value_helper("allowed_integer: 1")
            }

            #[test]
            fn disallows_non_string_keys() {
                assert!(matches!(
                    helpers::create_format_map::<EncryptedMap<StubCipher>>("123: xxx")
                        .to_internal(None)
                        .unwrap_err(),
                    FormatToInternalMapError::NonStringKey(_)
                ))
            }

            fn assert_allowed_value_helper(key_value_str: &str) {
                assert!(matches!(
                    helpers::create_format_map::<EncryptedMap<StubCipher>>(key_value_str)
                        .to_internal(Some(&PartialEncryptionConfig::EncryptedRegex(
                            regex::Regex::new("^allowed").unwrap().into()
                        )))
                        .unwrap_err(),
                    FormatToInternalMapError::PlaintextWhenEncrypted(_)
                ))
            }
        }

        mod decrypted {
            use crate::*;

            use super::helpers;

            #[test]
            fn transforms_decrypted_yaml_map() {
                assert_eq!(
                    RopsMap::mock(),
                    RopsFileFormatMap::<DecryptedMap, YamlFileFormat>::mock().to_internal().unwrap()
                )
            }

            #[test]
            fn disallows_non_string_keys() {
                assert!(matches!(
                    helpers::create_format_map::<DecryptedMap>("123: xxx").to_internal().unwrap_err(),
                    FormatToInternalMapError::NonStringKey(_)
                ))
            }

            #[test]
            fn dissallows_out_of_range_integers() {
                assert!(matches!(
                    helpers::create_format_map::<DecryptedMap>(&format!("invalid_integer: {}", u64::MAX))
                        .to_internal()
                        .unwrap_err(),
                    FormatToInternalMapError::IntegerOutOfRange(_)
                ))
            }
        }

        mod helpers {
            use crate::*;

            pub fn create_format_map<S: RopsMapState>(key_value_str: &str) -> RopsFileFormatMap<S, YamlFileFormat> {
                RopsFileFormatMap::<S, YamlFileFormat>::from_inner_map(serde_yaml::from_str::<serde_yaml::Mapping>(key_value_str).unwrap())
            }
        }
    }
}

mod rops_file {
    use crate::*;

    #[cfg(all(feature = "aes-gcm", feature = "sha2"))]
    mod aes_gcm_sha2 {
        use super::*;

        type EncryptedRopsFile = RopsFile<EncryptedFile<AES256GCM, SHA512>, YamlFileFormat>;
        type DecryptedRopsFile = RopsFile<DecryptedFile<SHA512>, YamlFileFormat>;

        #[test]
        fn serializes_decrypted_rops_file() {
            FileFormatTestUtils::assert_serialization::<YamlFileFormat, DecryptedRopsFile>()
        }

        #[test]
        fn deserializes_decrypted_rops_file() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, DecryptedRopsFile>()
        }

        #[test]
        fn serializes_encrypted_rops_file() {
            FileFormatTestUtils::assert_serialization::<YamlFileFormat, EncryptedRopsFile>()
        }

        #[test]
        fn deserializes_encrypted_rops_file() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, EncryptedRopsFile>()
        }

        #[test]
        fn encrypts_rops_file() {
            IntegrationsTestUtils::set_private_keys();

            assert_eq!(
                DecryptedRopsFile::mock(),
                DecryptedRopsFile::mock()
                    .encrypt::<AES256GCM, YamlFileFormat>()
                    .unwrap()
                    .decrypt()
                    .unwrap()
            )
        }

        #[test]
        fn encrypts_rops_file_with_saved_parameters() {
            IntegrationsTestUtils::set_private_keys();

            assert_eq!(
                EncryptedRopsFile::mock(),
                DecryptedRopsFile::mock()
                    .encrypt_with_saved_parameters(SavedParameters::mock())
                    .unwrap()
            )
        }

        #[test]
        fn decrypts_rops_file() {
            IntegrationsTestUtils::set_private_keys();

            assert_eq!(DecryptedRopsFile::mock(), EncryptedRopsFile::mock().decrypt().unwrap())
        }

        #[test]
        fn decrypts_rops_file_and_saves_parameters() {
            IntegrationsTestUtils::set_private_keys();

            assert_eq!(
                (DecryptedRopsFile::mock(), SavedParameters::mock()),
                EncryptedRopsFile::mock().decrypt_and_save_parameters().unwrap()
            )
        }

        #[test]
        fn decryption_disallows_mac_mismatch() {
            IntegrationsTestUtils::set_private_keys();

            assert!(matches!(
                RopsFile::<_, YamlFileFormat> {
                    map: RopsFileFormatMap::mock_other(),
                    metadata: RopsFileMetadata::mock()
                }
                .decrypt::<YamlFileFormat>()
                .unwrap_err(),
                RopsFileDecryptError::MacMismatch(_, _)
            ))
        }
    }
}

mod metadata {
    mod core {
        #[cfg(all(feature = "aes-gcm", feature = "sha2"))]
        mod aes_gcm_sha_2 {
            use crate::*;

            #[test]
            fn serializes_decrypted_metadata() {
                FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFileMetadata<DecryptedMetadata<SHA512>>>()
            }

            #[test]
            fn deserializes_decrypted_metadata() {
                FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFileMetadata<DecryptedMetadata<SHA512>>>()
            }

            #[test]
            fn serializes_encrypted_metadata() {
                FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFileMetadata<EncryptedMetadata<AES256GCM, SHA512>>>()
            }

            #[test]
            fn deserializes_encrypted_metadata() {
                FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFileMetadata<EncryptedMetadata<AES256GCM, SHA512>>>()
            }
        }
    }

    #[cfg(feature = "age")]
    mod age {
        use crate::*;

        #[test]
        fn serializes_rops_file_age_metadata() {
            FileFormatTestUtils::assert_serialization::<YamlFileFormat, IntegrationMetadataUnit<AgeIntegration>>()
        }

        #[test]
        fn deserializes_rops_file_age_metadata() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, AgeConfig>()
        }
    }
}
