use crate::*;

pub struct RopsFileBuilder<F: FileFormat> {
    plaintext_map: F::Map,
    partial_encryption: Option<PartialEncryptionConfig>,
    mac_only_encrypted: Option<bool>,
    #[cfg(feature = "age")]
    pub(crate) age_key_ids: Vec<<AgeIntegration as Integration>::KeyId>,
    #[cfg(feature = "aws-kms")]
    pub(crate) aws_kms_key_ids: Vec<<AwsKmsIntegration as Integration>::KeyId>,
}

impl<F: FileFormat> RopsFileBuilder<F> {
    pub fn new(plaintext_map: F::Map) -> Self {
        Self {
            plaintext_map,
            partial_encryption: None,
            mac_only_encrypted: None,
            #[cfg(feature = "age")]
            age_key_ids: Vec::new(),
            #[cfg(feature = "aws-kms")]
            aws_kms_key_ids: Vec::new(),
        }
    }

    pub fn with_partial_encryption(mut self, partial_encryption: PartialEncryptionConfig) -> Self {
        self.partial_encryption = Some(partial_encryption);
        self
    }

    pub fn mac_only_encrypted(mut self) -> Self {
        self.mac_only_encrypted = Some(true);
        self
    }

    pub fn add_integration_key<I: Integration>(mut self, key_id: I::KeyId) -> Self {
        key_id.append_to_builder(&mut self);
        self
    }

    pub fn encrypt<C: Cipher, H: Hasher>(self) -> Result<RopsFile<EncryptedFile<C, H>, F>, RopsFileEncryptError> {
        #[rustfmt::skip]
        let Self { plaintext_map, partial_encryption, mac_only_encrypted, .. } = self;

        let data_key = DataKey::new();

        let decrypted_map = plaintext_map.decrypted_to_internal()?;

        let mac = Mac::<H>::compute(
            MacOnlyEncryptedConfig::new(mac_only_encrypted, partial_encryption.as_ref()),
            &decrypted_map,
        );

        let encrypted_map_result = decrypted_map.encrypt(&data_key, partial_encryption.as_ref());

        let mut integration_metadata = IntegrationMetadata::default();
        #[cfg(feature = "age")]
        integration_metadata.add_keys::<AgeIntegration>(self.age_key_ids, &data_key)?;
        #[cfg(feature = "aws-kms")]
        integration_metadata.add_keys::<AwsKmsIntegration>(self.aws_kms_key_ids, &data_key)?;

        let encrypted_metadata_result = RopsFileMetadata {
            intregation: integration_metadata,
            last_modified: LastModifiedDateTime::now(),
            mac,
            partial_encryption,
            mac_only_encrypted,
        }
        .encrypt(&data_key);

        RopsFile::from_parts_results(encrypted_map_result, encrypted_metadata_result)
    }
}

// Redundant to test combinations of file formats, integrations, ciphers and hashers if the
// respective trait implementations are well tested.
#[cfg(all(test, feature = "yaml", feature = "age", feature = "aes-gcm", feature = "sha2"))]
mod tests {
    use super::*;

    #[test]
    fn encrypts_with_builder() {
        AgeIntegration::set_mock_private_key_env_var();

        let builder_rops_file =
            RopsFileBuilder::<YamlFileFormat>::new(RopsFileFormatMap::<DecryptedMap, YamlFileFormat>::mock().into_inner_map())
                .with_partial_encryption(MockTestUtil::mock())
                .mac_only_encrypted()
                .add_integration_key::<AgeIntegration>(MockTestUtil::mock())
                .encrypt::<AES256GCM, SHA512>()
                .unwrap()
                .decrypt::<YamlFileFormat>()
                .unwrap();

        assert_eq!(&RopsFileFormatMap::mock(), builder_rops_file.map());
        assert_ne!(&RopsFileMetadata::mock(), builder_rops_file.metadata());
    }
}
