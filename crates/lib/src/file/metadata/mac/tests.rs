#[cfg(feature = "sha2")]
mod sha2 {
    use indexmap::indexmap;

    use crate::*;

    #[test]
    fn computes_mac() {
        assert_eq!(
            Mac::mock(),
            Mac::<SHA512>::compute(MacOnlyEncryptedConfig::mock(), &RopsMap::mock())
        )
    }

    #[test]
    fn protects_against_collection_reordering() {
        assert_ne!(mac_from_collection(&[1, 2, 3]), mac_from_collection(&[3, 2, 1]));

        fn mac_from_collection(ints: &[i64]) -> Mac<SHA512> {
            let collection = ints.iter().map(|int| RopsTree::Leaf(RopsValue::Integer(*int))).collect();

            let map = RopsMap(indexmap! {
                "collection".to_string() => RopsTree::Sequence(collection)
            });

            Mac::compute(MacOnlyEncryptedConfig::mock(), &map)
        }
    }

    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use super::*;

        #[test]
        fn encrypts_mac() {
            let data_key = DataKey::mock();
            let last_modified = LastModifiedDateTime::mock();

            let encrypted = Mac::<SHA512>::mock().encrypt::<AES256GCM>(&data_key, &last_modified).unwrap();
            let decrypted = encrypted.decrypt(&data_key, &last_modified).unwrap();

            assert_eq!(Mac::mock(), decrypted)
        }

        #[test]
        fn encrypts_with_saved_nonce() {
            assert_eq!(
                EncryptedMac::<AES256GCM, SHA512>::mock(),
                Mac::mock()
                    .encrypt_with_saved_nonce(&DataKey::mock(), &LastModifiedDateTime::mock(), SavedMacNonce::mock())
                    .unwrap()
            );
        }

        #[test]
        fn decrypts_mac() {
            assert_eq!(
                Mac::mock(),
                EncryptedMac::<AES256GCM, SHA512>::mock()
                    .decrypt(&DataKey::mock(), &LastModifiedDateTime::mock())
                    .unwrap()
            )
        }

        #[test]
        fn decrypts_and_saves_nonce() {
            let (decrypted_mac, saved_mac_nonce) = EncryptedMac::<AES256GCM, SHA512>::mock()
                .decrypt_and_save_nonce(&DataKey::mock(), &LastModifiedDateTime::mock())
                .unwrap();

            assert_eq!(Mac::mock(), decrypted_mac);
            assert_eq!(SavedMacNonce::mock(), saved_mac_nonce);
        }

        #[test]
        fn protects_against_nonce_reuse() {
            let mac = Mac::mock();
            let data_key = DataKey::mock();
            let last_modified = LastModifiedDateTime::mock();

            let encrypted_mock_mac = mac
                .clone()
                .encrypt_with_saved_nonce::<AES256GCM>(&data_key, &last_modified, SavedMacNonce::mock())
                .unwrap();

            let other_saved_nonce = SavedMacNonce::<AES256GCM, SHA512>::new(
                Mac::compute(MacOnlyEncryptedConfig::mock(), &RopsMap::mock_other()),
                Nonce::mock(),
            );

            let encrypted_with_other_mac = mac.encrypt_with_saved_nonce(&data_key, &last_modified, other_saved_nonce).unwrap();

            assert_ne!(encrypted_mock_mac, encrypted_with_other_mac)
        }
    }
}
