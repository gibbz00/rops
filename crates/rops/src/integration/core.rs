use std::{env::VarError, fmt::Debug, path::PathBuf};

use crate::*;

const ROPS_APPLICATION_NAME: &str = "rops";

pub trait Integration: Sized {
    const NAME: &'static str;
    type KeyId: IntegrationKeyId<Self>;
    type PrivateKey;
    type Config: IntegrationConfig<Self>;

    fn private_key_env_var_name() -> String {
        format!("ROPS_{}", Self::NAME.to_uppercase())
    }

    fn private_key_file_path_override_env_var_name() -> String {
        format!("ROPS_{}_KEY_FILE", Self::NAME.to_uppercase())
    }

    fn private_keys_from_env() -> IntegrationResult<Vec<Self::PrivateKey>> {
        match std::env::var(Self::private_key_env_var_name()) {
            Ok(found_string) => found_string.split(',').map(Self::parse_private_key).collect(),
            Err(env_var_error) => match env_var_error {
                VarError::NotPresent => Ok(Vec::default()),
                VarError::NotUnicode(os_str) => Err(IntegrationError::EnvVarNotUnicode(os_str)),
            },
        }
    }

    fn private_keys_from_default_key_file() -> IntegrationResult<Vec<Self::PrivateKey>> {
        let integration_key_file = match std::env::var_os(Self::private_key_file_path_override_env_var_name()) {
            Some(os_string) => PathBuf::from(os_string),
            None => directories::BaseDirs::new()
                .ok_or(IntegrationError::NoHomeDir)?
                .config_local_dir()
                .join(ROPS_APPLICATION_NAME)
                .join(format!("{}_keys", Self::NAME)),
        };

        match integration_key_file.exists() {
            true => std::fs::read_to_string(integration_key_file)?
                .lines()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty())
                .map(Self::parse_private_key)
                .collect(),
            false => Ok(Vec::new()),
        }
    }

    fn retrieve_private_keys() -> IntegrationResult<Vec<Self::PrivateKey>> {
        let mut private_key_strings = Vec::<Self::PrivateKey>::new();

        // TODO: Expand key retrieval methods, see README.md
        private_key_strings.append(&mut Self::private_keys_from_env()?);
        private_key_strings.append(&mut Self::private_keys_from_default_key_file()?);

        Ok(private_key_strings)
    }

    fn parse_key_id(key_id_str: &str) -> IntegrationResult<Self::KeyId>;

    fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey>;

    fn encrypt_data_key(key_id: &Self::KeyId, data_key: &DataKey) -> IntegrationResult<String>;

    fn decrypt_data_key(key_id: &Self::KeyId, encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>>;

    fn select_metadata_units_field(integration_metadata: &mut IntegrationMetadata) -> &mut Vec<IntegrationMetadataUnit<Self>>;
}

pub trait IntegrationConfig<I: Integration>: Debug + PartialEq {
    const INCLUDE_DATA_KEY_CREATED_AT: bool;

    fn new(key_id: I::KeyId) -> Self;

    fn key_id(&self) -> &I::KeyId;
}

#[cfg(test)]
mod tests {
    use super::*;

    const STUB_KEYS: &[&str] = &["key1", "key2"];

    #[test]
    fn gets_private_key_env_var_name() {
        assert_eq!("ROPS_STUB", StubIntegration::private_key_env_var_name())
    }

    #[test]
    fn gets_private_key_file_path_override_env_var_name() {
        assert_eq!("ROPS_STUB_KEY_FILE", StubIntegration::private_key_file_path_override_env_var_name())
    }

    #[test]
    fn gets_private_key_from_env() {
        let var_name = StubIntegration::private_key_env_var_name();
        std::env::set_var(&var_name, "key1,key2");

        assert_eq!(STUB_KEYS, StubIntegration::private_keys_from_env().unwrap().as_slice());

        std::env::remove_var(&var_name);
    }

    const STUB_KEY_FILE_CONTENTS: &str = "
        key1
        key2
    ";

    #[test]
    #[serial_test::serial]
    fn gets_private_key_from_default_key_file() {
        let rops_config_dir = directories::BaseDirs::new().unwrap().config_local_dir().join(ROPS_APPLICATION_NAME);

        let created_config_dir = match rops_config_dir.is_dir() {
            true => false,
            false => {
                std::fs::create_dir_all(&rops_config_dir).unwrap();
                true
            }
        };

        let stub_keys_path = rops_config_dir.join(format!("{}_keys", StubIntegration::NAME));

        std::fs::write(&stub_keys_path, STUB_KEY_FILE_CONTENTS).unwrap();

        assert_eq!(STUB_KEYS, StubIntegration::private_keys_from_default_key_file().unwrap().as_slice());

        match created_config_dir {
            true => std::fs::remove_dir_all(rops_config_dir).unwrap(),
            false => std::fs::remove_file(stub_keys_path).unwrap(),
        }
    }

    #[test]
    #[serial_test::serial]
    fn gets_private_key_from_default_key_file_with_location_override() {
        let temp_dir = tempfile::tempdir().unwrap();

        let key_file_override_path = temp_dir.path().join("keys_override");

        std::fs::write(&key_file_override_path, STUB_KEY_FILE_CONTENTS).unwrap();

        let override_var_name = StubIntegration::private_key_file_path_override_env_var_name();
        std::env::set_var(&override_var_name, key_file_override_path.as_os_str());

        assert_eq!(STUB_KEYS, StubIntegration::private_keys_from_default_key_file().unwrap());

        std::env::remove_var(override_var_name)
    }
}
