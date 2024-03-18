use indexmap::IndexMap;

use crate::*;

impl RopsMap<DecryptedMap> {
    pub fn encrypt<C: Cipher>(
        self,
        data_key: &DataKey,
        optional_partial_encryption: Option<&PartialEncryptionConfig>,
    ) -> Result<RopsMap<EncryptedMap<C>>, C::Error> {
        Self::encrypt_recursive_impl(self, data_key, optional_partial_encryption, &None)
    }

    pub fn encrypt_with_saved_nonces<C: Cipher>(
        self,
        data_key: &DataKey,
        optional_partial_encryption: Option<&PartialEncryptionConfig>,
        saved_nonces: &SavedRopsMapNonces<C>,
    ) -> Result<RopsMap<EncryptedMap<C>>, C::Error> {
        Self::encrypt_recursive_impl(self, data_key, optional_partial_encryption, &Some(saved_nonces))
    }

    fn encrypt_recursive_impl<C: Cipher>(
        self,
        data_key: &DataKey,
        optional_partial_encryption: Option<&PartialEncryptionConfig>,
        saved_nonces: &Option<&SavedRopsMapNonces<C>>,
    ) -> Result<RopsMap<EncryptedMap<C>>, C::Error> {
        return encrypt_map_recursive(
            self,
            data_key,
            optional_partial_encryption.into(),
            &KeyPath::default(),
            saved_nonces,
        );

        fn encrypt_map_recursive<Ci: Cipher>(
            decrypted_map: RopsMap<DecryptedMap>,
            data_key: &DataKey,
            resolved_partial_encryption: ResolvedPartialEncryption,
            key_path: &KeyPath,
            optional_saved_nonces: &Option<&SavedRopsMapNonces<Ci>>,
        ) -> Result<RopsMap<EncryptedMap<Ci>>, Ci::Error> {
            let mut encrypted_map = RopsMap(IndexMap::with_capacity(decrypted_map.len()));
            for (key, decrypted_sub_tree) in decrypted_map.0 {
                let key_path = key_path.join(&key);
                let mut resolved_partial_encryption = resolved_partial_encryption;

                if let ResolvedPartialEncryption::No(partial_encryption_config) = resolved_partial_encryption {
                    resolved_partial_encryption = partial_encryption_config.resolve(key_path.last())
                }

                encrypted_map.insert(
                    key,
                    encrypt_tree_recursive(
                        decrypted_sub_tree,
                        data_key,
                        resolved_partial_encryption,
                        &key_path,
                        optional_saved_nonces,
                    )?,
                );
            }

            Ok(encrypted_map)
        }

        fn encrypt_tree_recursive<Ci: Cipher>(
            decrypted_tree: RopsTree<DecryptedMap>,
            data_key: &DataKey,
            resolved_partial_encryption: ResolvedPartialEncryption,
            key_path: &KeyPath,
            optional_saved_nonces: &Option<&SavedRopsMapNonces<Ci>>,
        ) -> Result<RopsTree<EncryptedMap<Ci>>, Ci::Error> {
            Ok(match decrypted_tree {
                RopsTree::Sequence(sequence) => RopsTree::Sequence(
                    sequence
                        .into_iter()
                        .map(|sub_tree| {
                            encrypt_tree_recursive(sub_tree, data_key, resolved_partial_encryption, key_path, optional_saved_nonces)
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                RopsTree::Map(decrypted_map) => RopsTree::Map(encrypt_map_recursive(
                    decrypted_map,
                    data_key,
                    resolved_partial_encryption,
                    key_path,
                    optional_saved_nonces,
                )?),
                RopsTree::Null => RopsTree::Null,
                RopsTree::Leaf(value) => match resolved_partial_encryption.escape_encryption() {
                    true => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(value)),
                    false => {
                        let nonce = optional_saved_nonces
                            .and_then(|saved_nonces| saved_nonces.get((key_path, &value)).cloned())
                            .unwrap_or_else(Nonce::new);
                        RopsTree::Leaf(RopsMapEncryptedLeaf::Encrypted(value.encrypt(nonce, data_key, key_path)?))
                    }
                },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use crate::*;

        #[test]
        fn encrypts_map_with_saved_nonces() {
            pretty_assertions::assert_eq!(
                RopsMap::<EncryptedMap<AES256GCM>>::mock(),
                RopsMap::<DecryptedMap>::mock()
                    .encrypt_with_saved_nonces(&DataKey::mock(), MockTestUtil::mock(), &SavedRopsMapNonces::mock())
                    .unwrap()
            )
        }

        #[test]
        fn encrypts_map_without_saving_nonces() {
            let decrypted_map = RopsMap::<DecryptedMap>::mock();
            let data_key = DataKey::mock();
            let encrypted_map = decrypted_map.encrypt(&data_key, None).unwrap();

            pretty_assertions::assert_ne!(RopsMap::<EncryptedMap<AES256GCM>>::mock(), encrypted_map);
            pretty_assertions::assert_eq!(RopsMap::mock(), encrypted_map.decrypt(&data_key).unwrap())
        }
    }
}
