use std::{env::VarError, fmt::Debug};

use crate::*;

pub trait Integration: Sized {
    const NAME: &'static str;
    type KeyId;
    type PrivateKey;
    type Config: IntegrationConfig<Self>;

    fn private_key_env_var_name() -> String {
        format!("ROPS_{}", Self::NAME.to_uppercase())
    }

    fn private_key_strings_from_env() -> IntegrationResult<Vec<String>> {
        match std::env::var(Self::private_key_env_var_name()) {
            Ok(found_string) => Ok(found_string.split(',').map(ToString::to_string).collect()),
            Err(env_var_error) => match env_var_error {
                VarError::NotPresent => Ok(Vec::default()),
                VarError::NotUnicode(os_str) => Err(IntegrationError::EnvVarNotUnicode(os_str)),
            },
        }
    }

    fn retrieve_private_keys() -> IntegrationResult<Vec<Self::PrivateKey>> {
        let mut private_key_strings = Vec::<String>::new();

        // TODO: Expand key retrieval methods, see README.md
        private_key_strings.append(&mut Self::private_key_strings_from_env()?);

        private_key_strings
            .into_iter()
            .map(Self::parse_private_key)
            .collect::<Result<Vec<_>, _>>()
    }

    fn parse_key_id(key_id_str: &str) -> IntegrationResult<Self::KeyId>;

    fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey>;

    fn encrypt_data_key(key_id: &Self::KeyId, data_key: &DataKey) -> IntegrationResult<String>;

    fn decrypt_data_key(key_id: &Self::KeyId, encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>>;
}

pub trait IntegrationConfig<I: Integration>: Debug + PartialEq {
    const INCLUDE_DATA_KEY_CREATED_AT: bool;

    fn key_id(&self) -> &I::KeyId;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gets_private_key_env_var_name() {
        assert_eq!("ROPS_STUB", StubIntegration::private_key_env_var_name())
    }

    #[test]
    fn gets_private_key_from_env() {
        let var_name = StubIntegration::private_key_env_var_name();
        std::env::set_var(&var_name, "key1,key2");

        assert_eq!(
            &["key1", "key2"],
            StubIntegration::private_key_strings_from_env().unwrap().as_slice()
        );

        std::env::remove_var(&var_name);
    }
}
