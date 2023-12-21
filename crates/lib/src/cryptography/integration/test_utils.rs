use crate::*;

pub trait IntegrationTestUtils: Integration {
    fn set_mock_private_key_env_var() {
        std::env::set_var(Self::private_key_env_var_name(), Self::mock_private_key_str())
    }

    fn mock_public_key_str() -> &'static str;

    fn mock_public_key() -> Self::PublicKey {
        Self::parse_public_key(Self::mock_public_key_str()).unwrap()
    }

    fn assert_parses_public_key() {
        Self::mock_public_key();
    }

    fn mock_private_key_str() -> &'static str;

    fn mock_private_key() -> Self::PrivateKey {
        Self::parse_private_key(Self::mock_private_key_str()).unwrap()
    }

    fn assert_parses_private_key() {
        Self::mock_private_key();
    }

    fn mock_encrypted_data_key_str() -> &'static str;

    fn assert_encrypts_data_key() {
        let expected_data_key = DataKey::mock();
        let encrypted_data_key = Self::encrypt_data_key(&Self::mock_public_key(), &expected_data_key).unwrap();
        let found_data_key = Self::decrypt_data_key(&Self::mock_private_key(), &encrypted_data_key).unwrap();
        assert_eq!(expected_data_key, found_data_key);
    }

    fn assert_decrypts_data_key() {
        assert_eq!(
            DataKey::mock(),
            Self::decrypt_data_key(&Self::mock_private_key(), Self::mock_encrypted_data_key_str()).unwrap()
        )
    }
}
