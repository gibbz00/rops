use std::{borrow::Cow, collections::HashMap};

use indexmap::IndexMap;

use crate::*;

impl<C: Cipher> RopsMap<EncryptedMap<C>> {
    pub fn decrypt(self, data_key: &DataKey) -> Result<RopsMap<DecryptedMap>, DecryptRopsValueError> {
        Self::decrypt_impl(self, data_key, &KeyPath::default(), &mut None)
    }

    pub fn decrypt_and_save_nonces(
        self,
        data_key: &DataKey,
    ) -> Result<(RopsMap<DecryptedMap>, SavedRopsMapNonces<C>), DecryptRopsValueError> {
        let mut saved_nonces = SavedRopsMapNonces(HashMap::new());
        Self::decrypt_impl(self, data_key, &KeyPath::default(), &mut Some(&mut saved_nonces)).map(|tree| (tree, saved_nonces))
    }

    fn decrypt_impl<Ci: Cipher>(
        map: RopsMap<EncryptedMap<Ci>>,
        data_key: &DataKey,
        key_path: &KeyPath,
        optional_saved_nonces: &mut Option<&mut SavedRopsMapNonces<Ci>>,
    ) -> Result<RopsMap<DecryptedMap>, DecryptRopsValueError> {
        return decrypt_map_recursive(map, data_key, key_path, optional_saved_nonces);

        fn decrypt_map_recursive<C: Cipher>(
            map: RopsMap<EncryptedMap<C>>,
            data_key: &DataKey,
            key_path: &KeyPath,
            optional_saved_nonces: &mut Option<&mut SavedRopsMapNonces<C>>,
        ) -> Result<RopsMap<DecryptedMap>, DecryptRopsValueError> {
            let mut decrypted_map = IndexMap::with_capacity(map.len());

            for (key, sub_tree) in map.0 {
                let sub_key_path = key_path.join(&key);
                decrypted_map.insert(
                    key,
                    decrypt_tree_recursive(sub_tree, data_key, &sub_key_path, optional_saved_nonces)?,
                );
            }

            Ok(decrypted_map.into())
        }

        fn decrypt_tree_recursive<C: Cipher>(
            tree: RopsTree<EncryptedMap<C>>,
            data_key: &DataKey,
            key_path: &KeyPath,
            optional_saved_nonces: &mut Option<&mut SavedRopsMapNonces<C>>,
        ) -> Result<RopsTree<DecryptedMap>, DecryptRopsValueError> {
            Ok(match tree {
                RopsTree::Sequence(sequence) => sequence
                    .into_iter()
                    .map(|sub_tree| decrypt_tree_recursive(sub_tree, data_key, key_path, optional_saved_nonces))
                    .collect::<Result<Vec<_>, _>>()
                    .map(RopsTree::Sequence)?,
                RopsTree::Map(encrypted_map) => {
                    RopsTree::Map(decrypt_map_recursive(encrypted_map, data_key, key_path, optional_saved_nonces)?)
                }

                RopsTree::Null => RopsTree::Null,
                RopsTree::Leaf(encrypted_value) => RopsTree::Leaf(match optional_saved_nonces {
                    Some(saved_nonces) => {
                        let nonce = encrypted_value.nonce.clone();
                        let decrypted_value = encrypted_value.decrypt(data_key, key_path)?;
                        saved_nonces.insert((Cow::Owned(key_path.clone()), Cow::Owned(decrypted_value.clone())), nonce);
                        decrypted_value
                    }
                    None => encrypted_value.decrypt(data_key, key_path)?,
                }),
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
        fn decrypts_map() {
            assert_eq!(
                RopsMap::<DecryptedMap>::mock(),
                RopsMap::<EncryptedMap<AES256GCM>>::mock().decrypt(&DataKey::mock()).unwrap()
            )
        }

        #[test]
        fn decryption_can_save_nonces() {
            assert_eq!(
                (RopsMap::<DecryptedMap>::mock(), SavedRopsMapNonces::mock()),
                RopsMap::<EncryptedMap<AES256GCM>>::mock()
                    .decrypt_and_save_nonces(&DataKey::mock())
                    .unwrap()
            )
        }
    }
}
