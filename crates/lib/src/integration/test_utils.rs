use crate::*;

pub trait IntegrationTestUtils: Integration {
    fn mock_private_key_str() -> impl AsRef<str>;

    fn mock_encrypted_data_key_str() -> &'static str;

    fn set_mock_private_key_env_var() {
        std::env::set_var(Self::private_key_env_var_name(), Self::mock_private_key_str().as_ref())
    }

    fn mock_private_key() -> Self::PrivateKey {
        Self::parse_private_key(Self::mock_private_key_str()).unwrap()
    }
}
