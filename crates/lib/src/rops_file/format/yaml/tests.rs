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
                RopsFile::new(RopsFileFormatMap::mock_other(), RopsFileMetadata::mock())
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
