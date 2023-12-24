use std::{
    env::VarError,
    fmt::{Debug, Display},
};

use crate::*;

pub trait Integration {
    const NAME: &'static str;
    type PublicKey: Display;
    type PrivateKey;
    type Config: Debug + PartialEq;

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

    fn parse_public_key(public_key_str: &str) -> IntegrationResult<Self::PublicKey>;

    fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey>;

    fn encrypt_data_key(public_key: &Self::PublicKey, data_key: &DataKey) -> IntegrationResult<String>;

    fn decrypt_data_key(private_key: &Self::PrivateKey, encrypted_data_key: &str) -> IntegrationResult<DataKey>;
}

#[cfg(feature = "test-utils")]
pub use stub_integration::StubIntegration;
#[cfg(feature = "test-utils")]
mod stub_integration {
    use super::*;

    pub struct StubIntegration;

    impl Integration for StubIntegration {
        const NAME: &'static str = "stub";
        type PublicKey = String;
        type PrivateKey = ();
        type Config = ();

        fn parse_public_key(_public_key_str: &str) -> IntegrationResult<Self::PublicKey> {
            unimplemented!()
        }

        fn parse_private_key(_private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey> {
            unimplemented!()
        }

        fn encrypt_data_key(_public_key: &Self::PublicKey, _data_key: &DataKey) -> IntegrationResult<String> {
            unimplemented!()
        }

        fn decrypt_data_key(_private_key: &Self::PrivateKey, _encrypted_data_key: &str) -> IntegrationResult<DataKey> {
            unimplemented!()
        }
    }
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
