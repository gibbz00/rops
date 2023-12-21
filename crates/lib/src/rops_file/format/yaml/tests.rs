mod rops_file {
    use crate::*;

    #[cfg(all(feature = "aes-gcm", feature = "sha2"))]
    mod aes_gcm {
        use super::*;

        #[test]
        fn serializes_decrypted_rops_file() {
            FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFile<DecryptedFile<SHA512>, YamlFileFormat>>()
        }

        #[test]
        fn deserializes_decrypted_rops_file() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFile<DecryptedFile<SHA512>, YamlFileFormat>>()
        }

        #[test]
        fn serializes_encrypted_rops_file() {
            FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFile<EncryptedFile<AES256GCM, SHA512>, YamlFileFormat>>()
        }

        #[test]
        fn deserializes_encrypted_rops_file() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFile<EncryptedFile<AES256GCM, SHA512>, YamlFileFormat>>()
        }
    }
}

mod metadata {
    mod core {
        #[cfg(all(feature = "aes-gcm", feature = "sha2"))]
        mod aes_gcm_sha_2 {
            use crate::*;

            // TODO: test both encrypted and decrypted serialization

            #[test]
            fn serializes_metadata() {
                FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFileMetadata<DecryptedMetadata<SHA512>>>()
            }

            #[test]
            fn deserializes_metadata() {
                FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFileMetadata<DecryptedMetadata<SHA512>>>()
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
