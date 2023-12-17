use std::{borrow::Cow, collections::HashMap};

use derive_more::{Deref, DerefMut, From, Into};
use indexmap::IndexMap;

use crate::*;

#[derive(Debug, PartialEq, From, Into, Deref, DerefMut)]
pub struct RopsMap<S: RopsFileState>(indexmap::IndexMap<String, RopsTree<S>>);

#[derive(Debug, PartialEq)]
pub enum RopsTree<S: RopsFileState> {
    Sequence(Vec<RopsTree<S>>),
    Map(RopsMap<S>),
    Null,
    Leaf(S::RopsTreeLeaf),
}

// WORKAROUND: Non-cow tuple key doesn't allow saved_nounces.get((&key, &value))
#[derive(Debug, PartialEq, Deref, DerefMut)]
#[allow(clippy::complexity)]
pub struct SavedRopsTreeNonces<C: Cipher>(HashMap<(Cow<'static, KeyPath>, Cow<'static, RopsValue>), Nonce<C::NonceSize>>);

impl RopsMap<Decrypted> {
    pub fn encrypt<C: Cipher>(self, data_key: &DataKey) -> Result<RopsMap<Encrypted<C>>, C::Error> {
        Self::encrypt_recursive_impl(self, data_key, &None)
    }

    pub fn encrypt_with_saved_nonces<C: Cipher>(
        self,
        data_key: &DataKey,
        saved_nonces: &SavedRopsTreeNonces<C>,
    ) -> Result<RopsMap<Encrypted<C>>, C::Error> {
        Self::encrypt_recursive_impl(self, data_key, &Some(saved_nonces))
    }

    fn encrypt_recursive_impl<C: Cipher>(
        self,
        data_key: &DataKey,
        saved_nonces: &Option<&SavedRopsTreeNonces<C>>,
    ) -> Result<RopsMap<Encrypted<C>>, C::Error> {
        return encrypt_map_inner(self, data_key, &KeyPath::default(), saved_nonces);

        fn encrypt_map_inner<Ci: Cipher>(
            decrypted_map: RopsMap<Decrypted>,
            data_key: &DataKey,
            key_path: &KeyPath,
            optional_saved_nonces: &Option<&SavedRopsTreeNonces<Ci>>,
        ) -> Result<RopsMap<Encrypted<Ci>>, Ci::Error> {
            let mut encrypted_map = RopsMap(IndexMap::with_capacity(decrypted_map.len()));
            for (key, decrypted_sub_tree) in decrypted_map.0 {
                let key_path = key_path.join(&key);
                encrypted_map.insert(
                    key,
                    encrypt_recursive_inner(decrypted_sub_tree, data_key, &key_path, optional_saved_nonces)?,
                );
            }

            Ok(encrypted_map)
        }

        fn encrypt_recursive_inner<Ci: Cipher>(
            decrypted_tree: RopsTree<Decrypted>,
            data_key: &DataKey,
            key_path: &KeyPath,
            optional_saved_nonces: &Option<&SavedRopsTreeNonces<Ci>>,
        ) -> Result<RopsTree<Encrypted<Ci>>, Ci::Error> {
            Ok(match decrypted_tree {
                RopsTree::Sequence(sequence) => RopsTree::Sequence(
                    sequence
                        .into_iter()
                        .map(|sub_tree| encrypt_recursive_inner(sub_tree, data_key, key_path, optional_saved_nonces))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                RopsTree::Map(decrypted_map) => RopsTree::Map(encrypt_map_inner(decrypted_map, data_key, key_path, optional_saved_nonces)?),
                RopsTree::Null => RopsTree::Null,
                RopsTree::Leaf(value) => {
                    let nonce = optional_saved_nonces
                        .map(|saved_nonces| saved_nonces.get(&(Cow::Borrowed(key_path), Cow::Borrowed(&value))).cloned())
                        .flatten()
                        .unwrap_or_else(Nonce::new);
                    RopsTree::Leaf(value.encrypt(nonce, data_key, key_path)?)
                }
            })
        }
    }
}

impl<C: Cipher> RopsTree<Encrypted<C>> {
    pub fn decrypt(self, data_key: &DataKey) -> Result<RopsTree<Decrypted>, DecryptRopsValueError> {
        Self::recursive_decrypt_impl(self, data_key, &KeyPath::default(), &mut None)
    }

    pub fn decrypt_and_save_nonces(
        self,
        data_key: &DataKey,
    ) -> Result<(RopsTree<Decrypted>, SavedRopsTreeNonces<C>), DecryptRopsValueError> {
        let mut saved_nonces = SavedRopsTreeNonces(HashMap::new());
        Self::recursive_decrypt_impl(self, data_key, &KeyPath::default(), &mut Some(&mut saved_nonces)).map(|tree| (tree, saved_nonces))
    }

    fn recursive_decrypt_impl<Ci: Cipher>(
        tree: RopsTree<Encrypted<Ci>>,
        data_key: &DataKey,
        key_path: &KeyPath,
        optional_saved_nonces: &mut Option<&mut SavedRopsTreeNonces<Ci>>,
    ) -> Result<RopsTree<Decrypted>, DecryptRopsValueError> {
        Ok(match tree {
            RopsTree::Sequence(sequence) => sequence
                .into_iter()
                .map(|sub_tree| Self::recursive_decrypt_impl(sub_tree, data_key, key_path, optional_saved_nonces))
                .collect::<Result<Vec<_>, _>>()
                .map(RopsTree::Sequence)?,
            RopsTree::Map(encrypted_map) => {
                let mut decrypted_map = IndexMap::with_capacity(encrypted_map.len());

                for (key, sub_tree) in encrypted_map.0 {
                    let sub_key_path = key_path.join(&key);
                    decrypted_map.insert(
                        key,
                        Self::recursive_decrypt_impl(sub_tree, data_key, &sub_key_path, optional_saved_nonces)?,
                    );
                }

                RopsTree::Map(decrypted_map.into())
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

#[cfg(feature = "test-utils")]
mod mock {
    use indexmap::indexmap;

    use super::*;

    impl MockTestUtil for RopsTree<Decrypted> {
        fn mock() -> Self {
            Self::Map(MockTestUtil::mock())
        }
    }

    impl<C: Cipher> MockTestUtil for RopsTree<Encrypted<C>>
    where
        RopsMap<Encrypted<C>>: MockTestUtil,
    {
        fn mock() -> Self {
            Self::Map(MockTestUtil::mock())
        }
    }

    impl MockTestUtil for RopsMap<Decrypted> {
        fn mock() -> Self {
            Self(indexmap! {
                "hello".to_string() => RopsTree::Leaf(RopsValue::String("world!".to_string())),
                "nested_map".to_string() => RopsTree::Map(Self(indexmap! {
                        "null_key".to_string() => RopsTree::Null,
                        "array".to_string() => RopsTree::Sequence(vec![
                            RopsTree::Leaf(RopsValue::String("string".to_string())),
                            RopsTree::Map(Self(indexmap! {
                                "nested_map_in_array".to_string() => RopsTree::Map(Self(indexmap!{
                                    "integer".to_string() => RopsTree::Leaf(RopsValue::Integer(1234))
                                })),
                            })),
                            RopsTree::Map(Self(indexmap!{
                                "float".to_string() => RopsTree::Leaf(RopsValue::Float(1234.56789.to_string()))
                            })),
                        ]),
                    }
                )),
                "booleans".to_string() => RopsTree::Sequence(vec![
                    RopsTree::Leaf(RopsValue::Boolean(true)),
                    RopsTree::Leaf(RopsValue::Boolean(false))
                ])
            })
        }
    }

    impl<C: Cipher> MockTestUtil for SavedRopsTreeNonces<C>
    where
        RopsTree<Encrypted<C>>: MockTestUtil,
    {
        fn mock() -> Self {
            let mut saved_nonces = SavedRopsTreeNonces(HashMap::new());
            recurive_build(RopsTree::mock(), &mut saved_nonces, &DataKey::mock(), &KeyPath::default());
            return saved_nonces;

            fn recurive_build<Ci: Cipher>(
                tree: RopsTree<Encrypted<Ci>>,
                saved_nonces: &mut SavedRopsTreeNonces<Ci>,
                data_key: &DataKey,
                key_path: &KeyPath,
            ) {
                match tree {
                    RopsTree::Sequence(sequence) => sequence
                        .into_iter()
                        .for_each(|sub_tree| recurive_build(sub_tree, saved_nonces, data_key, key_path)),
                    RopsTree::Map(map) => map
                        .0
                        .into_iter()
                        .for_each(|(key, sub_tree)| recurive_build(sub_tree, saved_nonces, data_key, &key_path.join(&key))),
                    RopsTree::Null => (),
                    RopsTree::Leaf(encrypted_value) => {
                        let nonce = encrypted_value.nonce.clone();
                        let decrypted = encrypted_value.decrypt(data_key, key_path).unwrap();
                        saved_nonces.insert((Cow::Owned(key_path.clone()), Cow::Owned(decrypted)), nonce);
                    }
                }
            }
        }
    }

    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use super::*;

        impl MockTestUtil for RopsMap<Encrypted<AES256GCM>> {
            fn mock() -> Self {
                return Self(indexmap! {
                    "hello".to_string() => leaf("ENC[AES256_GCM,data:3S1E9am/,iv:WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=,tag:nQUDkuh0OR1cjR5hGC5jOw==,type:str]"),
                    "nested_map".to_string() => RopsTree::Map(Self(indexmap! {
                            "null_key".to_string() => RopsTree::Null,
                            "array".to_string() => RopsTree::Sequence(vec![
                                leaf("ENC[AES256_GCM,data:ANbeNrGp,iv:PRWGCPdOttPr5dlzT9te7WWCZ90J7+CvfY1vp60aADM=,tag:PvSLx4pLT5zRKOU0df8Xlg==,type:str]"),
                                RopsTree::Map(Self(indexmap! {
                                    "nested_map_in_array".to_string() => RopsTree::Map(Self(indexmap!{
                                        "integer".to_string() => leaf("ENC[AES256_GCM,data:qTW5qw==,iv:ugMxvR8YPwDgn2MbBpDX0lpCqzJY3GerhbA5jEKUbwE=,tag:d8utfA76C4XPzJyDfgE4Pw==,type:int]")
                                    })),
                                })),
                                RopsTree::Map(Self(indexmap!{
                                    "float".to_string() => leaf("ENC[AES256_GCM,data:/MTg0fCennyN8g==,iv:+/8+Ljm+cls7BbDYZnlg6NVFkrkw4GkEfWU2aGW57qE=,tag:26uMp2JmVAckySIaL2BLCg==,type:float]")
                                })),
                            ]),
                        })
                    ),
                    "booleans".to_string() => RopsTree::Sequence(vec![
                        leaf("ENC[AES256_GCM,data:bCdz2A==,iv:8kD+h1jClyVHBj9o2WZuAkjk+uD6A2lgNpcGljpQEhk=,tag:u3/fktl5HfFrVLERVvLRGw==,type:bool]"),
                        leaf("ENC[AES256_GCM,data:SgBh7wY=,iv:0s9Q9pQWbsZm2yHsmFalCzX0IqNb6ZqeY6QQYCWc+qU=,tag:OZb76BWCKbDLbcil4c8fYA==,type:bool]")
                    ])
                });

                fn leaf(encrpyted_value_str: &str) -> RopsTree<Encrypted<AES256GCM>> {
                    encrpyted_value_str.parse().map(RopsTree::Leaf).unwrap()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use crate::*;

        #[test]
        fn decrypts_tree() {
            assert_eq!(
                RopsTree::<Decrypted>::mock(),
                RopsTree::<Encrypted<AES256GCM>>::mock().decrypt(&DataKey::mock()).unwrap()
            )
        }

        #[test]
        fn decryption_can_save_nonces() {
            assert_eq!(
                (RopsTree::<Decrypted>::mock(), SavedRopsTreeNonces::mock()),
                RopsTree::<Encrypted<AES256GCM>>::mock()
                    .decrypt_and_save_nonces(&DataKey::mock())
                    .unwrap()
            )
        }

        #[test]
        fn encrypts_tree_with_saved_nonces() {
            assert_eq!(
                RopsMap::<Encrypted<AES256GCM>>::mock(),
                RopsMap::<Decrypted>::mock()
                    .encrypt_with_saved_nonces(&DataKey::mock(), &SavedRopsTreeNonces::mock())
                    .unwrap()
            )
        }

        #[test]
        fn encrypts_tree_without_saving_nonces() {
            let decrypted_tree_map = RopsMap::<Decrypted>::mock();
            let data_key = DataKey::mock();
            let encrypted_tree = decrypted_tree_map.encrypt(&data_key).unwrap();

            assert_ne!(RopsMap::<Encrypted<AES256GCM>>::mock(), encrypted_tree);
            assert_eq!(
                RopsTree::Map(MockTestUtil::mock()),
                RopsTree::Map(encrypted_tree).decrypt(&data_key).unwrap()
            )
        }
    }
}
