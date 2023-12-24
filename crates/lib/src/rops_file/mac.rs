use std::{fmt::Display, marker::PhantomData, str::FromStr};

use derive_more::Display;
use hex::FromHexError;

use crate::*;

const MAC_ENCRYPTED_ONLY_INIT_BYTES: [u8; 32] = [
    0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52, 0x7b, 0x10, 0x34, 0xf3, 0xd1, 0x47, 0xbe, 0xb, 0xb, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72,
    0xc6, 0xfd, 0xad, 0xec, 0x81, 0x76, 0xf2, 0x7d, 0x69,
];

// SOPS stores the hex formatted byte representation of the computed MAC, hence the doubling in
// size. The buffer contains in other words UTF-8 byte codes the hex string encoded from the
// computed MAC, and not the computed MAC itself.
//
// TEMP(HACK): Inner buffer should ideally be a GenericArray<u8, Sum<H::OutputSize, H::OutputSize>>.
// But because where clauses aren't inferred in any function signature containing Mac<H>, a Vec is
// used instead. https://github.com/rust-lang/rust/issues/20671
//
// NOTE: Non-constant equality checking is currently protected against timing attacks
// by requiring that the MAC must be decrypted before being compared.
#[impl_tools::autoimpl(Debug, Clone, PartialEq)]
pub struct Mac<H: Hasher>(Vec<u8>, PhantomData<H>);

impl<H: Hasher> FromStr for Mac<H> {
    type Err = FromHexError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        hex::decode(str).map(|_| Self(str.as_bytes().to_vec(), PhantomData))
    }
}

impl<H: Hasher> Display for Mac<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            std::str::from_utf8(&self.0).expect("internal buffer does not represent a valid UTF-8 hex string")
        )
    }
}

impl<H: Hasher> Mac<H> {
    pub fn compute(from_encrypted_values_only: bool, decrypted_map: &RopsMap<DecryptedMap>) -> Self {
        let mut hasher = H::new();
        if from_encrypted_values_only {
            hasher.update(MAC_ENCRYPTED_ONLY_INIT_BYTES);
        }

        traverse_map(&mut hasher, from_encrypted_values_only, decrypted_map);

        return Mac(hex::encode_upper(hasher.finalize()).into_bytes(), PhantomData);

        fn traverse_map<Ha: Hasher>(hasher: &mut Ha, hash_encrypted_values_only: bool, map: &RopsMap<DecryptedMap>) {
            traverse_map_recursive(hasher, hash_encrypted_values_only, map);

            fn traverse_map_recursive<H: Hasher>(hasher: &mut H, hash_encrypted_values_only: bool, map: &RopsMap<DecryptedMap>) {
                for (_, tree) in map.iter() {
                    traverse_tree_recursive(hasher, hash_encrypted_values_only, tree)
                }
            }

            fn traverse_tree_recursive<H: Hasher>(hasher: &mut H, hash_encrypted_values_only: bool, tree: &RopsTree<DecryptedMap>) {
                match tree {
                    RopsTree::Sequence(sequence) => sequence
                        .iter()
                        .for_each(|sub_tree| traverse_tree_recursive(hasher, hash_encrypted_values_only, sub_tree)),
                    RopsTree::Map(map) => traverse_map_recursive(hasher, hash_encrypted_values_only, map),
                    RopsTree::Null => (),
                    RopsTree::Leaf(value) => {
                        // TODO: use hash_encrypted_only once partial encryption is added
                        hasher.update(value.as_bytes())
                    }
                }
            }
        }
    }

    pub fn encrypt<C: Cipher>(
        self,
        data_key: &DataKey,
        last_modified_date_time: &LastModifiedDateTime,
    ) -> Result<EncryptedMac<C, H>, C::Error> {
        self.encrypt_impl(data_key, last_modified_date_time, None)
    }

    pub fn encrypt_with_saved_nonce<C: Cipher>(
        self,
        data_key: &DataKey,
        last_modified_date_time: &LastModifiedDateTime,
        saved_mac_nonce: SavedMacNonce<C, H>,
    ) -> Result<EncryptedMac<C, H>, C::Error> {
        self.encrypt_impl(data_key, last_modified_date_time, Some(saved_mac_nonce))
    }

    fn encrypt_impl<C: Cipher>(
        self,
        data_key: &DataKey,
        last_modified_date_time: &LastModifiedDateTime,
        optional_saved_mac_nonce: Option<SavedMacNonce<C, H>>,
    ) -> Result<EncryptedMac<C, H>, C::Error> {
        let nonce = match optional_saved_mac_nonce {
            // IMPROVEMENT: throw error if saved nonce didn't match?
            Some(saved_mac_nonce) => saved_mac_nonce.get_or_create(&self),
            None => Nonce::new(),
        };

        let mut in_place_buffer = self.0;

        let authorization_tag = C::encrypt(
            &nonce,
            data_key,
            &mut in_place_buffer,
            last_modified_date_time.as_ref().to_rfc3339().as_bytes(),
        )?;

        Ok(EncryptedMac(
            EncryptedRopsValue {
                data: in_place_buffer.into(),
                authorization_tag,
                nonce,
                value_variant: RopsValueVariant::String,
            },
            PhantomData,
        ))
    }
}

#[derive(Display)]
#[display(fmt = "{}", "self.0")]
#[impl_tools::autoimpl(Debug, PartialEq)]
pub struct EncryptedMac<C: Cipher, H: Hasher>(EncryptedRopsValue<C>, PhantomData<H>);

// WORKAROUND: https://jeltef.github.io/derive_more/derive_more/from_str.html
// does not seem to support a #[fromstr] (as of 12/2023).
impl<C: Cipher, H: Hasher> FromStr for EncryptedMac<C, H> {
    type Err = <EncryptedRopsValue<C> as FromStr>::Err;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        str.parse().map(|encrypted_value| Self(encrypted_value, PhantomData))
    }
}

impl<C: Cipher, H: Hasher> EncryptedMac<C, H> {
    pub fn decrypt(self, data_key: &DataKey, last_modified_date_time: &LastModifiedDateTime) -> Result<Mac<H>, C::Error> {
        self.decrypt_impl(data_key, last_modified_date_time).map(|(mac, _)| mac)
    }

    #[allow(clippy::type_complexity)]
    pub fn decrypt_and_save_nonce(
        self,
        data_key: &DataKey,
        last_modified_date_time: &LastModifiedDateTime,
    ) -> Result<(Mac<H>, SavedMacNonce<C, H>), C::Error> {
        self.decrypt_impl(data_key, last_modified_date_time)
            .map(|(mac, nonce)| (mac.clone(), SavedMacNonce::new(mac, nonce)))
    }

    #[allow(clippy::type_complexity)]
    fn decrypt_impl(
        self,
        data_key: &DataKey,
        last_modified_date_time: &LastModifiedDateTime,
    ) -> Result<(Mac<H>, Nonce<C::NonceSize>), C::Error> {
        let mut in_place_buffer = Vec::from(self.0.data);
        C::decrypt(
            &self.0.nonce,
            data_key,
            &mut in_place_buffer,
            last_modified_date_time.as_ref().to_rfc3339().as_bytes(),
            &self.0.authorization_tag,
        )?;

        let mac = Mac(in_place_buffer, PhantomData);
        Ok((mac.clone(), self.0.nonce))
    }
}

pub use saved_mac_nonce::SavedMacNonce;
mod saved_mac_nonce {
    use crate::*;

    #[impl_tools::autoimpl(Debug, PartialEq)]
    pub struct SavedMacNonce<C: Cipher, H: Hasher>(Mac<H>, Nonce<C::NonceSize>);

    impl<C: Cipher, H: Hasher> SavedMacNonce<C, H> {
        pub fn new(mac: Mac<H>, nonce: Nonce<C::NonceSize>) -> Self {
            Self(mac, nonce)
        }

        pub fn get_or_create(self, mac: &Mac<H>) -> Nonce<C::NonceSize> {
            match &self.0 == mac {
                true => self.1,
                false => Nonce::new(),
            }
        }
    }

    #[cfg(feature = "test-utils")]
    mod mock {
        use super::*;

        impl<C: Cipher, H: Hasher> MockTestUtil for SavedMacNonce<C, H>
        where
            Mac<H>: MockTestUtil,
            EncryptedMac<C, H>: MockTestUtil,
        {
            fn mock() -> Self {
                Self::new(Mac::mock(), EncryptedMac::<C, H>::mock().0.nonce)
            }
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    #[cfg(feature = "sha2")]
    mod sha2 {
        use super::*;

        impl MockDisplayTestUtil for Mac<SHA512> {
            fn mock_display() -> String {
                "A0FBBFF515AC1EF88827C911653675DE4155901880355C59BA4FE4043395A0DE5EA77762EB3CAC54CC6F2B37EDDD916127A32566E810B0A5DADFA2F60B061331".to_string()
            }
        }

        impl MockTestUtil for Mac<SHA512> {
            fn mock() -> Self {
                Self(Self::mock_display().into_bytes(), PhantomData)
            }
        }

        #[cfg(feature = "aes-gcm")]
        mod aes_gcm {
            use super::*;

            impl MockTestUtil for EncryptedMac<AES256GCM, SHA512> {
                fn mock() -> Self {
                    Self(Self::mock_display().parse().unwrap(), PhantomData)
                }
            }

            impl MockDisplayTestUtil for EncryptedMac<AES256GCM, SHA512> {
                fn mock_display() -> String {
                    "ENC[AES256_GCM,data:W1CX5S5kbJ6f4uKuo6G5083Ekp50RAzqheQjbMEJpF1eZ7+d1/KSrLWIWjqZlyvzTDB1aMWp8xcOmCRCKyGn2cZCrr8SXU1yxpWW/42xue48LjFB0PVPt7YNTUtKrkb7KXOuvIrZ5HOXgoGpahopVCh06mG/T3hEHm/i2z/pzwk=,iv:fSPQ/8OhW8Mw2GMBHsO+qnhN4aKIN2sJYMNfjuxM+A8=,tag:kzpxGxIx4bVstvZrtMSFGQ==,type:str]".to_string()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "sha2")]
    mod sha2 {
        use crate::*;

        #[test]
        fn computes_mac() {
            assert_eq!(Mac::mock(), Mac::<SHA512>::compute(false, &RopsMap::mock()))
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

                let other_saved_nonce = SavedMacNonce::<AES256GCM, SHA512>::new(Mac::compute(false, &RopsMap::mock_other()), Nonce::mock());

                let encrypted_with_other_mac = mac.encrypt_with_saved_nonce(&data_key, &last_modified, other_saved_nonce).unwrap();

                assert_ne!(encrypted_mock_mac, encrypted_with_other_mac)
            }
        }
    }
}
