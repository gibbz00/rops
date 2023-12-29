use crate::*;

pub trait IntegrationTestUtils: Integration {
    fn set_mock_private_key_env_var() {
        std::env::set_var(Self::private_key_env_var_name(), Self::mock_private_key_str().as_ref())
    }

    fn mock_key_id_str() -> impl AsRef<str>;

    fn mock_key_id() -> Self::KeyId {
        Self::parse_key_id(Self::mock_key_id_str().as_ref()).unwrap()
    }

    fn assert_parses_key_id() {
        Self::mock_key_id();
    }

    fn mock_private_key_str() -> impl AsRef<str>;

    fn mock_private_key() -> Self::PrivateKey {
        Self::parse_private_key(Self::mock_private_key_str()).unwrap()
    }

    fn assert_parses_private_key() {
        Self::mock_private_key();
    }

    fn mock_encrypted_data_key_str() -> &'static str;

    fn assert_encrypts_data_key() {
        Self::set_mock_private_key_env_var();

        let expected_data_key = DataKey::mock();
        let encrypted_data_key = Self::encrypt_data_key(&Self::mock_key_id(), &expected_data_key).unwrap();
        let found_data_key = Self::decrypt_data_key(&Self::mock_key_id(), &encrypted_data_key).unwrap().unwrap();
        assert_eq!(expected_data_key, found_data_key);
    }

    fn assert_decrypts_data_key() {
        Self::set_mock_private_key_env_var();

        assert_eq!(
            DataKey::mock(),
            Self::decrypt_data_key(&Self::mock_key_id(), Self::mock_encrypted_data_key_str())
                .unwrap()
                .unwrap()
        )
    }
}

pub use stub_integration::StubIntegration;
mod stub_integration {

    use super::*;

    pub struct StubIntegration;

    impl Integration for StubIntegration {
        const NAME: &'static str = "stub";
        type KeyId = ();
        type PrivateKey = ();
        type Config = StubIntegrationConfig;

        fn parse_key_id(_key_id_str: &str) -> IntegrationResult<Self::KeyId> {
            unimplemented!()
        }

        fn parse_private_key(_private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey> {
            unimplemented!()
        }

        fn encrypt_data_key(_key_id: &Self::KeyId, _data_key: &DataKey) -> IntegrationResult<String> {
            unimplemented!()
        }

        fn decrypt_data_key(_key_id: &Self::KeyId, _encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>> {
            unimplemented!()
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct StubIntegrationConfig(String);

    impl IntegrationConfig<StubIntegration> for StubIntegrationConfig {
        const INCLUDE_DATA_KEY_CREATED_AT: bool = false;

        fn key_id(&self) -> &<StubIntegration as Integration>::KeyId {
            &()
        }
    }
}
