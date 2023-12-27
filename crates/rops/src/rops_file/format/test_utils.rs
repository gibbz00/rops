use std::fmt::{Debug, Display};

use serde::{de::DeserializeOwned, Serialize};

use crate::*;

pub trait MockFileFormatUtil<F: FileFormat> {
    fn mock_format_display() -> String;
}

pub struct FileFormatTestUtils;

impl FileFormatTestUtils {
    pub fn assert_serialization<F: FileFormat, T: MockTestUtil + MockFileFormatUtil<F> + Serialize>() {
        pretty_assertions::assert_eq!(T::mock_format_display(), F::serialize_to_string(&T::mock()).unwrap())
    }

    pub fn assert_deserialization<F: FileFormat, T: MockTestUtil + MockFileFormatUtil<F> + DeserializeOwned + Debug + PartialEq>() {
        pretty_assertions::assert_eq!(T::mock(), F::deserialize_from_str(&T::mock_format_display()).unwrap())
    }
}

pub trait FileFormatTestSuiteUtils: FileFormat {
    fn key_value_string(key: impl Display, value: impl Display) -> String;

    fn key_value_map<S: RopsMapState>(key: impl Display, value: impl Display) -> RopsFileFormatMap<S, Self> {
        Self::create_format_map(&Self::key_value_string(key, value))
    }

    fn create_format_map<S: RopsMapState>(key_value_str: &str) -> RopsFileFormatMap<S, Self>;
}

#[macro_export]
macro_rules! generate_file_format_test_suite {
    ($file_format:tt) => {
        mod adapters {
            mod encrypted {
                use std::fmt::Display;

                use $crate::*;

                #[cfg(feature = "aes-gcm")]
                mod aes_gcm {
                    use super::*;

                    #[test]
                    fn adapts_to_internal() {
                        assert_eq!(
                            RopsMap::mock(),
                            RopsFileFormatMap::<EncryptedMap<AES256GCM>, $file_format>::mock()
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
                            $file_format::create_format_map::<EncryptedMap<AES256GCM>>(&indoc::formatdoc! {"
                                {}
                                {}",
                                $file_format::key_value_string("escaped", "something"),
                                $file_format::key_value_string("encrypted", EncryptedRopsValue::<AES256GCM>::mock_display())
                            })
                            .to_internal(Some(&PartialEncryptionConfig::UnencryptedSuffix("escaped".to_string())))
                            .unwrap()
                        )
                    }
                }

                #[test]
                fn disallows_boolean_values_when_encrypted() {
                    assert_allowed_value_helper("disallowed_boolean", true)
                }

                #[test]
                fn disallows_integer_values_when_encrypted() {
                    assert_allowed_value_helper("disallowed_integer", 1)
                }

                #[test]
                fn disallows_non_string_keys() {
                    assert!(matches!(
                        $file_format::key_value_map::<EncryptedMap<StubCipher>>(123, "xxx")
                            .to_internal(None)
                            .unwrap_err(),
                        FormatToInternalMapError::NonStringKey(_)
                    ))
                }

                fn assert_allowed_value_helper(key: impl Display, value: impl Display) {
                    assert!(matches!(
                        $file_format::key_value_map::<EncryptedMap<StubCipher>>(key, value)
                            .to_internal(None)
                            .unwrap_err(),
                        FormatToInternalMapError::PlaintextWhenEncrypted(_)
                    ))
                }
            }

            mod decrypted {
                use $crate::*;

                #[test]
                fn adapts_to_internal() {
                    assert_eq!(
                        RopsMap::mock(),
                        RopsFileFormatMap::<DecryptedMap, $file_format>::mock().to_internal().unwrap()
                    )
                }

                #[test]
                fn disallows_non_string_keys() {
                    assert!(matches!(
                        $file_format::key_value_map::<DecryptedMap>(123, "xxx").to_internal().unwrap_err(),
                        FormatToInternalMapError::NonStringKey(_)
                    ))
                }

                #[test]
                fn dissallows_out_of_range_integers() {
                    assert!(matches!(
                        $file_format::key_value_map::<DecryptedMap>("invalid_integer", u64::MAX)
                            .to_internal()
                            .unwrap_err(),
                        FormatToInternalMapError::IntegerOutOfRange(_)
                    ))
                }
            }
        }

        mod rops_file {
            use $crate::*;

            #[cfg(all(feature = "aes-gcm", feature = "sha2"))]
            mod aes_gcm_sha2 {
                use super::*;

                type EncryptedRopsFile = RopsFile<EncryptedFile<AES256GCM, SHA512>, $file_format>;
                type DecryptedRopsFile = RopsFile<DecryptedFile<SHA512>, $file_format>;

                #[test]
                fn serializes_decrypted_rops_file() {
                    FileFormatTestUtils::assert_serialization::<$file_format, DecryptedRopsFile>()
                }

                #[test]
                fn deserializes_decrypted_rops_file() {
                    FileFormatTestUtils::assert_deserialization::<$file_format, DecryptedRopsFile>()
                }

                #[test]
                fn serializes_encrypted_rops_file() {
                    FileFormatTestUtils::assert_serialization::<$file_format, EncryptedRopsFile>()
                }

                #[test]
                fn deserializes_encrypted_rops_file() {
                    FileFormatTestUtils::assert_deserialization::<$file_format, EncryptedRopsFile>()
                }

                #[test]
                fn encrypts_rops_file() {
                    IntegrationsTestUtils::set_private_keys();

                    assert_eq!(
                        DecryptedRopsFile::mock(),
                        DecryptedRopsFile::mock()
                            .encrypt::<AES256GCM, $file_format>()
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
                        RopsFile::<_, $file_format> {
                            map: RopsFileFormatMap::mock_other(),
                            metadata: RopsFileMetadata::mock()
                        }
                        .decrypt::<$file_format>()
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
                    use $crate::*;

                    #[test]
                    fn serializes_decrypted_metadata() {
                        FileFormatTestUtils::assert_serialization::<$file_format, RopsFileMetadata<DecryptedMetadata<SHA512>>>()
                    }

                    #[test]
                    fn deserializes_decrypted_metadata() {
                        FileFormatTestUtils::assert_deserialization::<$file_format, RopsFileMetadata<DecryptedMetadata<SHA512>>>()
                    }

                    #[test]
                    fn serializes_encrypted_metadata() {
                        FileFormatTestUtils::assert_serialization::<$file_format, RopsFileMetadata<EncryptedMetadata<AES256GCM, SHA512>>>()
                    }

                    #[test]
                    fn deserializes_encrypted_metadata() {
                        FileFormatTestUtils::assert_deserialization::<$file_format, RopsFileMetadata<EncryptedMetadata<AES256GCM, SHA512>>>()
                    }
                }
            }

            #[cfg(feature = "age")]
            mod age {
                use $crate::*;

                #[test]
                fn serializes_rops_file_age_metadata() {
                    FileFormatTestUtils::assert_serialization::<$file_format, IntegrationMetadataUnit<AgeIntegration>>()
                }

                #[test]
                fn deserializes_rops_file_age_metadata() {
                    FileFormatTestUtils::assert_deserialization::<$file_format, AgeConfig>()
                }
            }
        }
    };
}
