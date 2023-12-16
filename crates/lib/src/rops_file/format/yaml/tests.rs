mod rops_file {
    use crate::*;

    #[test]
    fn serializes_decrypted_rops_file() {
        FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFile<Decrypted, YamlFileFormat>>()
    }

    #[test]
    fn deserializes_decrypted_rops_file() {
        FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFile<Decrypted, YamlFileFormat>>()
    }

    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use super::*;

        #[test]
        fn serializes_encrypted_rops_file() {
            FileFormatTestUtils::assert_serialization::<YamlFileFormat, RopsFile<Encrypted<AES256GCM>, YamlFileFormat>>()
        }

        #[test]
        fn deserializes_encrypted_rops_file() {
            FileFormatTestUtils::assert_deserialization::<YamlFileFormat, RopsFile<Encrypted<AES256GCM>, YamlFileFormat>>()
        }
    }
}

mod metadata {
    mod core {
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
