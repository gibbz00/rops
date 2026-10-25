use serde::{Deserialize, Serialize};

use crate::*;

/// Deserialized through `IntegrationMetadataDeserialize` and serialized through
/// `IntegrationMetadataSerialize`, as SSH keys are stored in the `age` field alongside
/// native age keys.
#[derive(Debug, Default, PartialEq, Deserialize)]
#[serde(try_from = "IntegrationMetadataDeserialize")]
pub struct IntegrationMetadata {
    #[cfg(feature = "aws-kms")]
    pub kms: IntegrationMetadataUnits<AwsKmsIntegration>,
    #[cfg(feature = "age")]
    pub age: IntegrationMetadataUnits<AgeIntegration>,
    /// Stored in the `age` field when serialized, as is done by `sops`.
    #[cfg(feature = "ssh")]
    pub ssh: IntegrationMetadataUnits<SshIntegration>,
}

impl Serialize for IntegrationMetadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        IntegrationMetadataSerialize::from(self).serialize(serializer)
    }
}

#[derive(Serialize)]
struct IntegrationMetadataSerialize<'a> {
    #[cfg(feature = "aws-kms")]
    #[serde(skip_serializing_if = "is_empty_units")]
    kms: &'a IntegrationMetadataUnits<AwsKmsIntegration>,
    #[cfg(feature = "age")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    age: Vec<AgeFieldUnit<'a>>,
}

#[cfg(feature = "aws-kms")]
fn is_empty_units<I: Integration>(units: &&IntegrationMetadataUnits<I>) -> bool {
    units.is_empty()
}

/// Entry of the `age` field, either native age or SSH.
#[cfg(feature = "age")]
#[derive(Serialize)]
#[serde(untagged)]
enum AgeFieldUnit<'a> {
    Age(&'a IntegrationMetadataUnit<AgeIntegration>),
    #[cfg(feature = "ssh")]
    Ssh(&'a IntegrationMetadataUnit<SshIntegration>),
}

impl<'a> From<&'a IntegrationMetadata> for IntegrationMetadataSerialize<'a> {
    fn from(integration_metadata: &'a IntegrationMetadata) -> Self {
        Self {
            #[cfg(feature = "aws-kms")]
            kms: &integration_metadata.kms,
            #[cfg(feature = "age")]
            age: {
                let age_units = integration_metadata.age.values().map(AgeFieldUnit::Age);

                #[cfg(feature = "ssh")]
                let age_units = age_units.chain(integration_metadata.ssh.values().map(AgeFieldUnit::Ssh));

                age_units.collect()
            },
        }
    }
}

#[derive(Deserialize)]
struct IntegrationMetadataDeserialize {
    #[cfg(feature = "aws-kms")]
    // Naming inconsistency inherited from SOPS, should ideally be named `aws_kms`
    // (a serde(alias = "kms") could be kept to supporting migrations.)
    #[serde(default)]
    kms: IntegrationMetadataUnits<AwsKmsIntegration>,
    #[cfg(feature = "age")]
    #[serde(default)]
    age: Vec<AgeFieldUnitDeserialize>,
}

/// Entry of the `age` field, told apart by the recipient's prefix as is done by `sops`.
#[cfg(feature = "age")]
#[derive(Deserialize)]
struct AgeFieldUnitDeserialize {
    recipient: String,
    created_at: Option<IntegrationCreatedAt>,
    #[serde(rename = "enc")]
    encrypted_data_key: String,
}

#[cfg(feature = "age")]
impl AgeFieldUnitDeserialize {
    const SSH_RECIPIENT_PREFIX: &'static str = "ssh-";

    fn is_ssh(&self) -> bool {
        self.recipient.trim().starts_with(Self::SSH_RECIPIENT_PREFIX)
    }

    fn into_unit<I: Integration>(self) -> IntegrationResult<IntegrationMetadataUnit<I>> {
        Ok(IntegrationMetadataUnit {
            config: I::Config::new(I::parse_key_id(&self.recipient)?),
            created_at: self.created_at,
            encrypted_data_key: self.encrypted_data_key,
        })
    }
}

impl TryFrom<IntegrationMetadataDeserialize> for IntegrationMetadata {
    type Error = IntegrationError;

    fn try_from(deserialized: IntegrationMetadataDeserialize) -> Result<Self, Self::Error> {
        #[allow(unused_mut)]
        let mut integration_metadata = Self {
            #[cfg(feature = "aws-kms")]
            kms: deserialized.kms,
            ..Default::default()
        };

        #[cfg(feature = "age")]
        for age_field_unit in deserialized.age {
            match age_field_unit.is_ssh() {
                #[cfg(feature = "ssh")]
                true => integration_metadata.ssh.insert(age_field_unit.into_unit()?),
                #[cfg(not(feature = "ssh"))]
                true => {
                    return Err(IntegrationError::KeyIdParsing(anyhow::anyhow!(
                        "SSH recipients require the 'ssh' feature of the 'rops' crate to be enabled"
                    )))
                }
                false => integration_metadata.age.insert(age_field_unit.into_unit()?),
            }
        }

        Ok(integration_metadata)
    }
}

impl IntegrationMetadata {
    pub fn add_keys<I: Integration>(&mut self, key_ids: impl IntoIterator<Item = I::KeyId>, data_key: &DataKey) -> IntegrationResult<()>
    where
        I::KeyId: Clone,
    {
        key_ids
            .into_iter()
            .map(|key_id| I::Config::new(key_id))
            .map(|integration_config| IntegrationMetadataUnit::<I>::new(integration_config, data_key))
            .try_for_each(|integration_metadata_unit_result| {
                I::select_metadata_units(self).insert(integration_metadata_unit_result?);
                Ok(())
            })
    }

    pub fn decrypt_data_key(&self) -> IntegrationResult<Option<DataKey>> {
        // In order of what is assumed to be quickest:

        // IMPROVEMENT: generialize if access to unit by simple reference becomes common.
        #[cfg(feature = "age")]
        if let Some(decrypt_result) = self.age.values().find_map(|age_metadata| {
            AgeIntegration::decrypt_data_key(&age_metadata.config.key_id, &age_metadata.encrypted_data_key).transpose()
        }) {
            return decrypt_result.map(Some);
        }

        #[cfg(feature = "ssh")]
        if let Some(decrypt_result) = self.ssh.values().find_map(|ssh_metadata| {
            SshIntegration::decrypt_data_key(&ssh_metadata.config.key_id, &ssh_metadata.encrypted_data_key).transpose()
        }) {
            return decrypt_result.map(Some);
        }

        #[cfg(feature = "aws-kms")]
        if let Some(decrypt_result) = self.kms.values().find_map(|aws_kms_metadata| {
            AwsKmsIntegration::decrypt_data_key(&aws_kms_metadata.config.key_id, &aws_kms_metadata.encrypted_data_key).transpose()
        }) {
            return decrypt_result.map(Some);
        }

        Ok(None)
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for IntegrationMetadata {
        fn mock() -> Self {
            Self {
                #[cfg(feature = "aws-kms")]
                kms: MockTestUtil::mock(),
                #[cfg(feature = "age")]
                age: MockTestUtil::mock(),
                #[cfg(feature = "ssh")]
                ssh: Default::default(),
            }
        }
    }
}

// Using age keys rather than stub integration to avoid setting adding test fields in
// `IntegrationMetadata`.
#[cfg(all(test, feature = "age"))]
mod tests {
    use super::*;

    #[test]
    fn adds_keys() {
        let mut integration_metadata = IntegrationMetadata::default();
        assert!(integration_metadata.age.is_empty());

        integration_metadata
            .add_keys::<AgeIntegration>(Some(<AgeIntegration as Integration>::KeyId::mock()), &DataKey::mock())
            .unwrap();

        assert!(!integration_metadata.age.is_empty())
    }
}

// SSH recipients share the `age` field with native age recipients.
#[cfg(all(test, feature = "ssh", feature = "yaml"))]
mod ssh_tests {
    use super::*;

    fn mixed_metadata() -> IntegrationMetadata {
        let mut integration_metadata = IntegrationMetadata::default();

        integration_metadata
            .add_keys::<AgeIntegration>(Some(<AgeIntegration as Integration>::KeyId::mock()), &DataKey::mock())
            .unwrap();
        integration_metadata
            .add_keys::<SshIntegration>(Some(<SshIntegration as Integration>::KeyId::mock()), &DataKey::mock())
            .unwrap();

        integration_metadata
    }

    #[test]
    fn serializes_both_kinds_to_age_field() {
        let serialized = serde_yaml::to_string(&mixed_metadata()).unwrap();

        assert_eq!(1, serialized.matches("age:").count());
        assert!(serialized.contains(&<AgeIntegration as Integration>::KeyId::mock_display()));
        assert!(serialized.contains(&<SshIntegration as Integration>::KeyId::mock_display()));
    }

    #[test]
    fn deserializes_age_field_by_recipient_kind() {
        let integration_metadata = mixed_metadata();
        let deserialized = serde_yaml::from_str::<IntegrationMetadata>(&serde_yaml::to_string(&integration_metadata).unwrap()).unwrap();

        assert_eq!(1, deserialized.age.len());
        assert_eq!(1, deserialized.ssh.len());
        assert_eq!(integration_metadata, deserialized);
    }

    #[test]
    fn rejects_invalid_ssh_recipient() {
        let invalid = "age:\n- recipient: ssh-ed25519 notakey\n  enc: abc\n";

        assert!(serde_yaml::from_str::<IntegrationMetadata>(invalid).is_err())
    }
}
