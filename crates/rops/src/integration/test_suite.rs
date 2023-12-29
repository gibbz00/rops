macro_rules! generate_integration_test_suite {
    ($integration:tt) => {
        #[test]
        fn parses_private_key() {
            <$integration as IntegrationTestUtils>::assert_parses_private_key()
        }

        #[test]
        fn parses_key_id() {
            <$integration as IntegrationTestUtils>::assert_parses_key_id()
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
        fn retrieves_private_key_from_env() {
            $integration::set_mock_private_key_env_var();

            assert!(!$integration::retrieve_private_keys().unwrap().is_empty())
        }
    };
}

pub(crate) use generate_integration_test_suite;
