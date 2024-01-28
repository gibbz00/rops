use crate::*;

pub struct RopsFileBuilder<F: FileFormat> {
    format_map: F::Map,
    partial_encryption: Option<PartialEncryptionConfig>,
    mac_only_encrypted: Option<bool>,
    pub(crate) integration_metadata_builder: IntegrationMetadataBuilder,
}

#[derive(Debug, thiserror::Error)]
pub enum RopsFileBuilderError {
    #[error(transparent)]
    Encrypt(#[from] RopsFileEncryptError),
    #[error(transparent)]
    IntegrationMetaData(#[from] IntegrationMetadataBuilderError),
}

impl<F: FileFormat> RopsFileBuilder<F> {
    pub fn new(plaintext_map: &str) -> Result<Self, F::DeserializeError> {
        Ok(Self {
            format_map: F::deserialize_from_str(plaintext_map)?,
            partial_encryption: None,
            mac_only_encrypted: None,
            integration_metadata_builder: Default::default(),
        })
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
        key_id.append_to_metadata_builder(&mut self.integration_metadata_builder);
        self
    }

    pub fn add_integration_keys<I: Integration>(self, key_ids: impl IntoIterator<Item = I::KeyId>) -> Self {
        key_ids.into_iter().fold(self, |mut builder, key_id| {
            builder = builder.add_integration_key::<I>(key_id);
            builder
        })
    }

    pub fn encrypt<C: Cipher, H: Hasher>(self) -> Result<RopsFile<EncryptedFile<C, H>, F>, RopsFileBuilderError> {
        #[rustfmt::skip]
        let Self { format_map: plaintext_map, partial_encryption, mac_only_encrypted, .. } = self;

        let data_key = DataKey::new();

        let decrypted_map = plaintext_map
            .decrypted_to_internal()
            .map_err(RopsFileEncryptError::FormatToIntenrnalMap)?;

        let mac = Mac::<H>::compute(
            MacOnlyEncryptedConfig::new(mac_only_encrypted, partial_encryption.as_ref()),
            &decrypted_map,
        );

        let encrypted_map_result = decrypted_map.encrypt(&data_key, partial_encryption.as_ref());

        let encrypted_metadata_result = RopsFileMetadata {
            intregation: self.integration_metadata_builder.into_integration_metadata(&data_key)?,
            last_modified: LastModifiedDateTime::now(),
            mac,
            partial_encryption,
            mac_only_encrypted,
        }
        .encrypt(&data_key);

        RopsFile::from_parts_results(encrypted_map_result, encrypted_metadata_result).map_err(Into::into)
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
            RopsFileBuilder::<YamlFileFormat>::new(&RopsFileFormatMap::<DecryptedMap, YamlFileFormat>::mock_format_display())
                .unwrap()
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
