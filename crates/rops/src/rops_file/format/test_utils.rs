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
    fn simple_map(key: impl Display, value: impl Display) -> String;

    fn key_value_map<S: RopsMapState>(key: impl Display, value: impl Display) -> RopsFileFormatMap<S, Self> {
        Self::create_format_map(&Self::simple_map(key, value))
    }

    fn create_format_map<S: RopsMapState>(key_value_str: &str) -> RopsFileFormatMap<S, Self> {
        RopsFileFormatMap::from_inner_map(Self::deserialize_from_str::<Self::Map>(key_value_str).unwrap())
    }
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
                        pretty_assertions::assert_eq!(
                            RopsMap::mock(),
                            RopsFileFormatMap::<EncryptedMap<AES256GCM>, $file_format>::mock()
                                .to_internal(MockTestUtil::mock())
                                .unwrap()
                        )
                    }

                    #[test]
                    fn adapts_from_internal() {
                        pretty_assertions::assert_eq!(
                            RopsFileFormatMap::<EncryptedMap<AES256GCM>, $file_format>::mock(),
                            RopsMap::mock().to_external()
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
                    pretty_assertions::assert_eq!(
                        RopsMap::mock(),
                        RopsFileFormatMap::<DecryptedMap, $file_format>::mock().to_internal().unwrap()
                    )
                }

                #[test]
                fn adapts_from_internal() {
                    pretty_assertions::assert_eq!(
                        RopsFileFormatMap::<DecryptedMap, $file_format>::mock(),
                        RopsMap::mock().to_external()
                    )
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
                        FileFormatTestUtils::assert_deserialization::<$file_format, RopsFileMetadata<EncryptedMetadata<AES256GCM, SHA512>>>(
                        )
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
