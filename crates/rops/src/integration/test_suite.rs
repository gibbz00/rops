macro_rules! generate_integration_test_suite {
    ($integration:tt) => {
        #[test]
        fn parses_private_key() {
            $integration::parse_private_key($integration::mock_private_key_str()).unwrap();
        }

        #[test]
        fn parses_key_id() {
            $integration::parse_key_id($integration::mock_key_id_str().as_ref()).unwrap();
        }

        #[test]
        fn encrypts_data_key() {
            $integration::set_mock_private_key_env_var();

            let expected_data_key = DataKey::mock();
            let encrypted_data_key = $integration::encrypt_data_key(&$integration::mock_key_id(), &expected_data_key).unwrap();
            let found_data_key = $integration::decrypt_data_key(&$integration::mock_key_id(), &encrypted_data_key)
                .unwrap()
                .unwrap();

            assert_eq!(expected_data_key, found_data_key);
        }

        #[test]
        fn decrypts_data_key() {
            $integration::set_mock_private_key_env_var();

            assert_eq!(
                DataKey::mock(),
                $integration::decrypt_data_key(&$integration::mock_key_id(), $integration::mock_encrypted_data_key_str())
                    .unwrap()
                    .unwrap()
            );
        }

        #[test]
        fn retrieves_private_key_from_env() {
            $integration::set_mock_private_key_env_var();

            assert!(!$integration::retrieve_private_keys().unwrap().is_empty())
        }
    };
}

pub(crate) use generate_integration_test_suite;
