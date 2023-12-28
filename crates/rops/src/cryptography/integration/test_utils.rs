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

pub use stub_integration::StubIntegration;
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

#[macro_export]
macro_rules! generate_integration_test_suite {
    ($integration:tt) => {
        #[test]
        fn parses_private_key() {
            <$integration as IntegrationTestUtils>::assert_parses_private_key()
        }

        #[test]
        fn parses_public_key() {
            <$integration as IntegrationTestUtils>::assert_parses_public_key()
        }

        #[test]
        fn encrypts_data_key() {
            <$integration as IntegrationTestUtils>::assert_encrypts_data_key()
        }

        #[test]
        fn decrypts_data_key() {
            <$integration as IntegrationTestUtils>::assert_decrypts_data_key()
        }

        #[test]
        fn retrieves_data_key_by_env() {
            $integration::set_mock_private_key_env_var();
            assert_eq!(
                DataKey::mock(),
                IntegrationMetadata::mock().data_key_from_age().unwrap().unwrap()
            )
        }
    };
}
