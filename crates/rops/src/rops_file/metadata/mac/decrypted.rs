use std::{fmt::Display, marker::PhantomData, str::FromStr};

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
pub struct Mac<H: Hasher>(pub(crate) Vec<u8>, pub(crate) PhantomData<H>);

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
    pub fn compute(mac_only_encrypted_config: MacOnlyEncryptedConfig<'_>, decrypted_map: &RopsMap<DecryptedMap>) -> Self {
        let mut hasher = H::new();

        if mac_only_encrypted_config.mac_only_encrypted {
            hasher.update(MAC_ENCRYPTED_ONLY_INIT_BYTES);
        }

        traverse_map(&mut hasher, mac_only_encrypted_config, decrypted_map);

        return Mac(hex::encode_upper(hasher.finalize()).into_bytes(), PhantomData);

        fn traverse_map<Ha: Hasher>(hasher: &mut Ha, mac_only_encrypted_config: MacOnlyEncryptedConfig<'_>, map: &RopsMap<DecryptedMap>) {
            traverse_map_recursive(hasher, mac_only_encrypted_config, map);

            fn traverse_map_recursive<H: Hasher>(
                hasher: &mut H,
                mac_only_encrypted_config: MacOnlyEncryptedConfig<'_>,
                map: &RopsMap<DecryptedMap>,
            ) {
                for (key, tree) in map.iter() {
                    let mut mac_only_encrypted_config = mac_only_encrypted_config;

                    if let ResolvedPartialEncrpytion::No(partial_encryption_config) = mac_only_encrypted_config.resolved_partial_encryption
                    {
                        mac_only_encrypted_config.resolved_partial_encryption = partial_encryption_config.resolve(key);
                    }

                    traverse_tree_recursive(hasher, mac_only_encrypted_config, tree)
                }
            }

            fn traverse_tree_recursive<H: Hasher>(
                hasher: &mut H,
                mac_only_encrypted_config: MacOnlyEncryptedConfig<'_>,
                tree: &RopsTree<DecryptedMap>,
            ) {
                match tree {
                    RopsTree::Sequence(sequence) => sequence
                        .iter()
                        .for_each(|sub_tree| traverse_tree_recursive(hasher, mac_only_encrypted_config, sub_tree)),
                    RopsTree::Map(map) => traverse_map_recursive(hasher, mac_only_encrypted_config, map),
                    RopsTree::Null => (),
                    RopsTree::Leaf(value) => {
                        #[rustfmt::skip]
                    let MacOnlyEncryptedConfig { mac_only_encrypted, resolved_partial_encryption } = mac_only_encrypted_config;

                        if !(resolved_partial_encryption.escape_encryption() && mac_only_encrypted) {
                            hasher.update(value.as_bytes())
                        }
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

        let authorization_tag = C::encrypt(&nonce, data_key, &mut in_place_buffer, &last_modified_date_time.to_bytes())?;

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

#[cfg(feature = "test-utils")]
mod mock {
    #[cfg(feature = "sha2")]
    mod sha2 {
        use std::marker::PhantomData;

        use crate::*;

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
    }
}
