// Dotenv stores flat strings only. The mocks below hold only what the format can
// represent: no booleans, integers, arrays, nulls or nested maps.

mod rops_file {
    use std::{fmt::Display, str::FromStr};

    use crate::*;

    impl<S: RopsFileState> MockFileFormatUtil<DotenvFileFormat> for RopsFile<S, DotenvFileFormat>
    where
        RopsFileFormatMap<S::MapState, DotenvFileFormat>: MockFileFormatUtil<DotenvFileFormat>,
        <S::MetadataState as RopsMetadataState>::Mac: MockDisplayTestUtil,
        <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
    {
        fn mock_format_display() -> String {
            format!(
                "{}{}",
                RopsFileFormatMap::<S::MapState, DotenvFileFormat>::mock_format_display(),
                metadata_lines::<S::MetadataState>()
            )
        }
    }

    fn metadata_lines<M: RopsMetadataState>() -> String
    where
        M::Mac: MockDisplayTestUtil,
    {
        let mut lines = String::new();

        #[cfg(feature = "age")]
        lines.push_str(&age_lines());

        #[cfg(feature = "aws-kms")]
        lines.push_str(&kms_lines());

        lines.push_str(&format!(
            "sops_lastmodified={}\nsops_mac={}\nsops_unencrypted_suffix={}\n",
            LastModifiedDateTime::mock_display(),
            <M::Mac as MockDisplayTestUtil>::mock_display(),
            PartialEncryptionConfig::mock_display()
        ));

        lines
    }

    #[cfg(feature = "aws-kms")]
    fn kms_lines() -> String {
        let AwsKeyId { profile, key_arn } = AwsKeyId::mock();
        // Same field order as the other formats: config fields, then created_at, then enc.
        let encrypted_data_key = AwsKmsIntegration::mock_encrypted_data_key_str().replace('\n', "\\n");
        format!(
            "sops_kms__list_0__map_arn={key_arn}\nsops_kms__list_0__map_aws_profile={profile}\nsops_kms__list_0__map_created_at={}\nsops_kms__list_0__map_enc={encrypted_data_key}\n",
            IntegrationCreatedAt::mock_display()
        )
    }

    #[cfg(feature = "age")]
    fn age_lines() -> String {
        // Multi-line PEM is written with the two characters `\n`, as sops does.
        let encrypted_data_key = AgeIntegration::mock_encrypted_data_key_str().replace('\n', "\\n");
        format!(
            "sops_age__list_0__map_enc={}\nsops_age__list_0__map_recipient={}\n",
            encrypted_data_key,
            <AgeIntegration as Integration>::KeyId::mock_display()
        )
    }
}

mod map {
    use crate::*;

    impl MockFileFormatUtil<DotenvFileFormat> for RopsFileFormatMap<DecryptedMap, DotenvFileFormat> {
        fn mock_format_display() -> String {
            "hello=world!\nescape_unencrypted=plaintext\n".to_string()
        }
    }

    #[cfg(feature = "aes-gcm")]
    impl MockFileFormatUtil<DotenvFileFormat> for RopsFileFormatMap<EncryptedMap<AES256GCM>, DotenvFileFormat> {
        fn mock_format_display() -> String {
            "hello=ENC[AES256_GCM,data:3S1E9am/,iv:WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=,tag:nQUDkuh0OR1cjR5hGC5jOw==,type:str]\nescape_unencrypted=plaintext\n".to_string()
        }
    }
}
