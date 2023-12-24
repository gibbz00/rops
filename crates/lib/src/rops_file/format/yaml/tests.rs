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
        fn decrypts_rops_file() {
            IntegrationsHelper::set_private_keys();

            assert_eq!(DecryptedRopsFile::mock(), EncryptedRopsFile::mock().decrypt().unwrap())
        }

        #[test]
        fn disallows_mac_mismatch() {
            IntegrationsHelper::set_private_keys();

            let rops_file = RopsFile {
                map: RopsFileFormatMap::mock_other(),
                metadata: RopsFileMetadata::mock(),
            };

            assert!(matches!(
                rops_file.decrypt::<YamlFileFormat>().unwrap_err(),
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
            FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFileAgeMetadata>()
        }

        #[test]
        fn deserializes_rops_file_age_metadata() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFileAgeMetadata>()
        }
    }
}
