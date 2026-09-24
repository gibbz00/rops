use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::*;

#[derive(Serialize, Deserialize)]
#[serde(bound = "F: FileFormat")]
#[impl_tools::autoimpl(Debug, PartialEq)]
pub struct RopsFile<S: RopsFileState, F: FileFormat>
where
    <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
{
    #[serde(flatten)]
    map: RopsFileFormatMap<S::MapState, F>,
    #[serde(rename = "sops")]
    metadata: RopsFileMetadata<S::MetadataState>,
}

impl<S: RopsFileState, F: FileFormat> RopsFile<S, F>
where
    <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
{
    pub fn new(map: impl ToExternalMap<S::MapState>, metadata: RopsFileMetadata<S::MetadataState>) -> Self {
        Self {
            map: map.to_external::<F>(),
            metadata,
        }
    }

    pub fn map(&self) -> &RopsFileFormatMap<S::MapState, F> {
        &self.map
    }

    pub fn into_inner_map(self) -> F::Map {
        self.map.into_inner_map()
    }

    pub fn metadata(&self) -> &RopsFileMetadata<S::MetadataState> {
        &self.metadata
    }

    // Not a public method of metadata as we don't want to expose mutable access to it.
    pub fn add_keys<I: Integration>(&mut self, key_ids: impl IntoIterator<Item = I::KeyId>) -> Result<(), RopsFileAddKeyError>
    where
        I::KeyId: Clone,
    {
        let data_key = self.metadata.retrieve_data_key()?;
        self.metadata.intregation.add_keys::<I>(key_ids, &data_key).map_err(Into::into)
    }

    pub fn add_keys_with_private_keys<I: Integration>(
        &mut self,
        key_ids: impl IntoIterator<Item = I::KeyId>,
        private_keys: &ExplicitPrivateKeys,
    ) -> Result<(), RopsFileAddKeyError>
    where
        I::KeyId: Clone,
    {
        let data_key = self.metadata.retrieve_data_key_with_private_keys(private_keys)?;
        self.metadata.intregation.add_keys::<I>(key_ids, &data_key).map_err(Into::into)
    }
}

impl<S: RopsFileState, F: FileFormat> Display for RopsFile<S, F>
where
    <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", F::serialize_to_string(self).expect("failed to serialize rops map"))
    }
}

#[derive(Debug, Error)]
pub enum RopsFileFromStrError {
    #[error("deserialize error")]
    Deserialize(anyhow::Error),
}

impl<S: RopsFileState, F: FileFormat> FromStr for RopsFile<S, F>
where
    <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
{
    type Err = RopsFileFromStrError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        F::deserialize_from_str(str).map_err(|error| RopsFileFromStrError::Deserialize(error.into()))
    }
}

impl<H: Hasher, F: FileFormat> RopsFile<DecryptedFile<H>, F> {
    pub fn set_map(mut self, other_map: RopsFileFormatMap<DecryptedMap, F>) -> Result<Self, FormatToInternalMapError> {
        if self.map != other_map {
            self.metadata.last_modified = LastModifiedDateTime::now();
        }

        let internal_other_map = other_map.to_internal()?;

        self.metadata.mac = Mac::<H>::compute(
            MacOnlyEncryptedConfig::new(self.metadata.mac_only_encrypted, self.metadata.partial_encryption.as_ref()),
            &internal_other_map,
        );

        self.map = internal_other_map.to_external();

        Ok(self)
    }

    /// Returns the removed integration medata unit, if any.
    pub fn remove_integration_key<I: Integration>(&mut self, key_id: &I::KeyId) -> IntegrationResult<Option<IntegrationMetadataUnit<I>>> {
        self.metadata.remove_integration_key(key_id)
    }

    pub fn encrypt<C: Cipher, Fo: FileFormat>(self) -> Result<RopsFile<EncryptedFile<C, H>, Fo>, RopsFileEncryptError> {
        let data_key = self.metadata.retrieve_data_key()?;
        self.encrypt_with_data_key(&data_key)
    }

    pub fn encrypt_with_private_keys<C: Cipher, Fo: FileFormat>(
        self,
        private_keys: &ExplicitPrivateKeys,
    ) -> Result<RopsFile<EncryptedFile<C, H>, Fo>, RopsFileEncryptError> {
        let data_key = self.metadata.retrieve_data_key_with_private_keys(private_keys)?;
        self.encrypt_with_data_key(&data_key)
    }

    fn encrypt_with_data_key<C: Cipher, Fo: FileFormat>(
        self,
        data_key: &DataKey,
    ) -> Result<RopsFile<EncryptedFile<C, H>, Fo>, RopsFileEncryptError> {
        let encrypted_map = self
            .map
            .to_internal()?
            .encrypt::<C>(data_key, self.metadata.partial_encryption.as_ref());
        let encrypted_metadata = self.metadata.encrypt::<C>(data_key);
        RopsFile::from_parts_results(encrypted_map, encrypted_metadata)
    }

    pub fn encrypt_with_saved_parameters<C: Cipher, Fo: FileFormat>(
        self,
        saved_parameters: SavedParameters<C, H>,
    ) -> Result<RopsFile<EncryptedFile<C, H>, Fo>, RopsFileEncryptError> {
        #[rustfmt::skip]
        let SavedParameters { data_key, saved_map_nonces, saved_mac_nonce } = saved_parameters;

        let encrypted_map =
            self.map
                .to_internal()?
                .encrypt_with_saved_nonces(&data_key, self.metadata.partial_encryption.as_ref(), &saved_map_nonces);

        let encrypted_metadata = self.metadata.encrypt_with_saved_mac_nonce::<C>(&data_key, saved_mac_nonce);
        RopsFile::from_parts_results(encrypted_map, encrypted_metadata)
    }
}

impl<C: Cipher, F: FileFormat, H: Hasher> RopsFile<EncryptedFile<C, H>, F> {
    pub fn decrypt<Fo: FileFormat>(self) -> Result<RopsFile<DecryptedFile<H>, Fo>, RopsFileDecryptError> {
        let (decrypted_metadata, data_key) = self.metadata.decrypt()?;
        Self::decrypt_map(self.map, decrypted_metadata, data_key)
    }

    pub fn decrypt_with_private_keys<Fo: FileFormat>(
        self,
        private_keys: &ExplicitPrivateKeys,
    ) -> Result<RopsFile<DecryptedFile<H>, Fo>, RopsFileDecryptError> {
        let (decrypted_metadata, data_key) = self.metadata.decrypt_with_private_keys(private_keys)?;
        Self::decrypt_map(self.map, decrypted_metadata, data_key)
    }

    fn decrypt_map<Fo: FileFormat>(
        map: RopsFileFormatMap<EncryptedMap<C>, F>,
        decrypted_metadata: RopsFileMetadata<DecryptedMetadata<H>>,
        data_key: DataKey,
    ) -> Result<RopsFile<DecryptedFile<H>, Fo>, RopsFileDecryptError> {
        let decrypted_map = map
            .to_internal(decrypted_metadata.partial_encryption.as_ref())?
            .decrypt(&data_key)?;
        Self::validate_mac(&decrypted_map, &decrypted_metadata)?;
        Ok(RopsFile::new(decrypted_map, decrypted_metadata))
    }

    #[allow(clippy::type_complexity)]
    pub fn decrypt_and_save_parameters<Fo: FileFormat>(
        self,
    ) -> Result<(RopsFile<DecryptedFile<H>, Fo>, SavedParameters<C, H>), RopsFileDecryptError> {
        let (decrypted_metadata, data_key, saved_mac_nonce) = self.metadata.decrypt_and_save_mac_nonce()?;
        Self::decrypt_map_and_save_parameters(self.map, decrypted_metadata, data_key, saved_mac_nonce)
    }

    #[allow(clippy::type_complexity)]
    pub fn decrypt_and_save_parameters_with_private_keys<Fo: FileFormat>(
        self,
        private_keys: &ExplicitPrivateKeys,
    ) -> Result<(RopsFile<DecryptedFile<H>, Fo>, SavedParameters<C, H>), RopsFileDecryptError> {
        let (decrypted_metadata, data_key, saved_mac_nonce) = self.metadata.decrypt_and_save_mac_nonce_with_private_keys(private_keys)?;
        Self::decrypt_map_and_save_parameters(self.map, decrypted_metadata, data_key, saved_mac_nonce)
    }

    #[allow(clippy::type_complexity)]
    fn decrypt_map_and_save_parameters<Fo: FileFormat>(
        map: RopsFileFormatMap<EncryptedMap<C>, F>,
        decrypted_metadata: RopsFileMetadata<DecryptedMetadata<H>>,
        data_key: DataKey,
        saved_mac_nonce: SavedMacNonce<C, H>,
    ) -> Result<(RopsFile<DecryptedFile<H>, Fo>, SavedParameters<C, H>), RopsFileDecryptError> {
        let (decrypted_map, saved_map_nonces) = map
            .to_internal(decrypted_metadata.partial_encryption.as_ref())?
            .decrypt_and_save_nonces(&data_key)?;

        Self::validate_mac(&decrypted_map, &decrypted_metadata)?;

        Ok((
            RopsFile::new(decrypted_map, decrypted_metadata),
            SavedParameters {
                data_key,
                saved_map_nonces,
                saved_mac_nonce,
            },
        ))
    }

    fn validate_mac(
        decrypted_map: &RopsMap<DecryptedMap>,
        decrypted_metadata: &RopsFileMetadata<DecryptedMetadata<H>>,
    ) -> Result<(), RopsFileDecryptError> {
        let computed_mac = Mac::<H>::compute(
            MacOnlyEncryptedConfig::new(
                decrypted_metadata.mac_only_encrypted,
                decrypted_metadata.partial_encryption.as_ref(),
            ),
            decrypted_map,
        );
        let stored_mac = &decrypted_metadata.mac;

        match &computed_mac != stored_mac {
            true => Err(RopsFileDecryptError::MacMismatch(computed_mac.to_string(), stored_mac.to_string())),
            false => Ok(()),
        }
    }

    pub(crate) fn from_parts_results(
        encrypted_map_result: Result<RopsMap<EncryptedMap<C>>, C::Error>,
        encrypted_metadata_result: Result<RopsFileMetadata<EncryptedMetadata<C, H>>, C::Error>,
    ) -> Result<Self, RopsFileEncryptError> {
        let encrypted_map = encrypted_map_result.map_err(|error| RopsFileEncryptError::MetadataEncryption(error.into()))?;
        let encrypted_metadata = encrypted_metadata_result.map_err(|error| RopsFileEncryptError::MetadataEncryption(error.into()))?;
        Ok(RopsFile::new(encrypted_map, encrypted_metadata))
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<S: RopsFileState, F: FileFormat> MockTestUtil for RopsFile<S, F>
    where
        RopsFileFormatMap<S::MapState, F>: MockTestUtil,
        RopsFileMetadata<S::MetadataState>: MockTestUtil,
        <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
    {
        fn mock() -> Self {
            Self {
                map: MockTestUtil::mock(),
                metadata: MockTestUtil::mock(),
            }
        }
    }
}

// Redundant to test combinations of file formats, integrations, ciphers and hashers if the
// respective trait implementations are well tested.
#[cfg(all(test, feature = "yaml", feature = "age", feature = "aes-gcm", feature = "sha2"))]
mod tests {
    use crate::*;

    type EncryptedRopsFile = RopsFile<EncryptedFile<AES256GCM, SHA512>, YamlFileFormat>;
    type DecryptedRopsFile = RopsFile<DecryptedFile<SHA512>, YamlFileFormat>;

    #[test]
    fn encrypts_rops_file() {
        AgeIntegration::set_mock_private_key_env_var();

        pretty_assertions::assert_eq!(
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
        AgeIntegration::set_mock_private_key_env_var();

        pretty_assertions::assert_eq!(
            EncryptedRopsFile::mock(),
            DecryptedRopsFile::mock()
                .encrypt_with_saved_parameters(SavedParameters::mock())
                .unwrap()
        )
    }

    #[test]
    fn decrypts_rops_file() {
        AgeIntegration::set_mock_private_key_env_var();

        pretty_assertions::assert_eq!(DecryptedRopsFile::mock(), EncryptedRopsFile::mock().decrypt().unwrap())
    }

    #[test]
    fn decrypts_rops_file_and_saves_parameters() {
        AgeIntegration::set_mock_private_key_env_var();

        pretty_assertions::assert_eq!(
            (DecryptedRopsFile::mock(), SavedParameters::mock()),
            EncryptedRopsFile::mock().decrypt_and_save_parameters().unwrap()
        )
    }

    fn explicit_age_private_keys(private_key: &age::x25519::Identity) -> ExplicitPrivateKeys {
        ExplicitPrivateKeys {
            age: vec![private_key.clone()],
            ..Default::default()
        }
    }

    #[test]
    fn decrypts_rops_file_with_private_keys() {
        pretty_assertions::assert_eq!(
            DecryptedRopsFile::mock(),
            EncryptedRopsFile::mock()
                .decrypt_with_private_keys(&explicit_age_private_keys(&AgeIntegration::mock_private_key()))
                .unwrap()
        )
    }

    #[test]
    fn decrypts_rops_file_and_saves_parameters_with_private_keys() {
        pretty_assertions::assert_eq!(
            (DecryptedRopsFile::mock(), SavedParameters::mock()),
            EncryptedRopsFile::mock()
                .decrypt_and_save_parameters_with_private_keys(&explicit_age_private_keys(&AgeIntegration::mock_private_key()))
                .unwrap()
        )
    }

    #[test]
    fn decryption_with_private_keys_ignores_env() {
        AgeIntegration::set_mock_private_key_env_var();

        let age_env_vars = || {
            [
                AgeIntegration::private_key_env_var_name(),
                AgeIntegration::private_key_file_path_override_env_var_name(),
            ]
            .map(std::env::var_os)
        };
        let age_env_vars_before = age_env_vars();

        assert!(matches!(
            EncryptedRopsFile::mock()
                .decrypt_with_private_keys::<YamlFileFormat>(&ExplicitPrivateKeys::default())
                .unwrap_err(),
            RopsFileDecryptError::Metadata(RopsFileMetadataDecryptError::DataKeyRetrieval(
                RopsFileMetadataDataKeyRetrievalError::MissingDataKey
            ))
        ));
        assert_eq!(age_env_vars_before, age_env_vars());
    }

    #[test]
    fn updates_recipients_with_private_keys() {
        let original_private_key = age::x25519::Identity::generate();
        let added_private_key = age::x25519::Identity::generate();

        let mut encrypted_rops_file =
            RopsFileBuilder::<YamlFileFormat>::new(&RopsFileFormatMap::<DecryptedMap, YamlFileFormat>::mock_format_display())
                .unwrap()
                .add_integration_key::<AgeIntegration>(original_private_key.to_public())
                .encrypt::<AES256GCM, SHA512>()
                .unwrap();

        encrypted_rops_file
            .add_keys_with_private_keys::<AgeIntegration>(
                Some(added_private_key.to_public()),
                &explicit_age_private_keys(&original_private_key),
            )
            .unwrap();

        let mut decrypted_rops_file = encrypted_rops_file
            .decrypt_with_private_keys::<YamlFileFormat>(&explicit_age_private_keys(&added_private_key))
            .unwrap();

        decrypted_rops_file
            .remove_integration_key::<AgeIntegration>(&original_private_key.to_public())
            .unwrap()
            .unwrap();

        let encrypted_rops_file = decrypted_rops_file
            .encrypt_with_private_keys::<AES256GCM, YamlFileFormat>(&explicit_age_private_keys(&added_private_key))
            .unwrap();

        assert!(encrypted_rops_file
            .metadata()
            .intregation
            .decrypt_data_key_with_private_keys(&explicit_age_private_keys(&original_private_key))
            .unwrap()
            .is_none());

        assert_eq!(
            &RopsFileFormatMap::mock(),
            encrypted_rops_file
                .decrypt_with_private_keys::<YamlFileFormat>(&explicit_age_private_keys(&added_private_key))
                .unwrap()
                .map()
        );
    }

    #[test]
    fn decryption_disallows_mac_mismatch() {
        AgeIntegration::set_mock_private_key_env_var();

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

    #[test]
    fn sets_map() {
        let rops_file = RopsFile::<DecryptedFile<SHA512>, YamlFileFormat>::mock();
        let new_rops_file = rops_file.set_map(RopsFileFormatMap::mock_other()).unwrap();

        assert_eq!(RopsFileFormatMap::mock_other(), new_rops_file.map);
        assert_ne!(LastModifiedDateTime::mock(), new_rops_file.metadata.last_modified);
        assert_eq!(
            Mac::<SHA512>::compute(MacOnlyEncryptedConfig::mock(), &RopsMap::mock_other()),
            Mac::<SHA512>::compute(MacOnlyEncryptedConfig::mock(), &new_rops_file.map.to_internal().unwrap())
        )
    }

    #[test]
    fn skips_updating_unmodified_map() {
        let rops_file = RopsFile::<DecryptedFile<SHA512>, YamlFileFormat>::mock()
            .set_map(RopsFileFormatMap::mock())
            .unwrap();
        assert_eq!(LastModifiedDateTime::mock(), rops_file.metadata.last_modified);
    }
}
