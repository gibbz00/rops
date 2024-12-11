use indexmap::indexmap;

use crate::*;

impl MockTestUtil for RopsMap<DecryptedMap> {
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
                            "float".to_string() => RopsTree::Leaf(RopsValue::Float(1234.56789.into()))
                        })),
                    ]),
                }
            )),
            "booleans".to_string() => RopsTree::Sequence(vec![
                RopsTree::Leaf(RopsValue::Boolean(true)),
                RopsTree::Leaf(RopsValue::Boolean(false))
            ]),
            "escape_unencrypted".to_string() => RopsTree::Leaf(RopsValue::String("plaintext".to_string()))
        })
    }
}

impl MockOtherTestUtil for RopsMap<DecryptedMap> {
    fn mock_other() -> Self {
        Self(indexmap::indexmap! {
            "mumbo".to_string() => RopsTree::Leaf(RopsValue::String("jumbo".to_string()))
        })
    }
}

impl<C: Cipher> MockTestUtil for SavedRopsMapNonces<C>
where
    RopsMap<EncryptedMap<C>>: MockTestUtil,
{
    fn mock() -> Self {
        let mut saved_nonces = SavedRopsMapNonces::default();
        recursive_build(
            RopsTree::Map(RopsMap::mock()),
            &mut saved_nonces,
            &DataKey::mock(),
            &KeyPath::default(),
        );
        return saved_nonces;

        fn recursive_build<Ci: Cipher>(
            tree: RopsTree<EncryptedMap<Ci>>,
            saved_nonces: &mut SavedRopsMapNonces<Ci>,
            data_key: &DataKey,
            key_path: &KeyPath,
        ) {
            match tree {
                RopsTree::Sequence(sequence) => sequence
                    .into_iter()
                    .for_each(|sub_tree| recursive_build(sub_tree, saved_nonces, data_key, key_path)),
                RopsTree::Map(map) => map
                    .0
                    .into_iter()
                    .for_each(|(key, sub_tree)| recursive_build(sub_tree, saved_nonces, data_key, &key_path.join(&key))),
                RopsTree::Null => (),
                RopsTree::Leaf(encrypted_map_leaf) => {
                    if let RopsMapEncryptedLeaf::Encrypted(encrypted_value) = encrypted_map_leaf {
                        let nonce = encrypted_value.nonce.clone();
                        let decrypted = encrypted_value.decrypt(data_key, key_path).unwrap();
                        saved_nonces.insert((key_path.clone(), decrypted), nonce);
                    }
                }
            }
        }
    }
}

#[cfg(feature = "aes-gcm")]
mod aes_gcm {
    use super::*;

    impl MockTestUtil for RopsMap<EncryptedMap<AES256GCM>> {
        fn mock() -> Self {
            Self(indexmap! {
                "hello".to_string() => encrypted_leaf("ENC[AES256_GCM,data:3S1E9am/,iv:WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=,tag:nQUDkuh0OR1cjR5hGC5jOw==,type:str]"),
                "nested_map".to_string() => RopsTree::Map(Self(indexmap! {
                        "null_key".to_string() => RopsTree::Null,
                        "array".to_string() => RopsTree::Sequence(vec![
                            encrypted_leaf("ENC[AES256_GCM,data:ANbeNrGp,iv:PRWGCPdOttPr5dlzT9te7WWCZ90J7+CvfY1vp60aADM=,tag:PvSLx4pLT5zRKOU0df8Xlg==,type:str]"),
                            RopsTree::Map(Self(indexmap! {
                                "nested_map_in_array".to_string() => RopsTree::Map(Self(indexmap!{
                                    "integer".to_string() => encrypted_leaf("ENC[AES256_GCM,data:qTW5qw==,iv:ugMxvR8YPwDgn2MbBpDX0lpCqzJY3GerhbA5jEKUbwE=,tag:d8utfA76C4XPzJyDfgE4Pw==,type:int]")
                                })),
                            })),
                            RopsTree::Map(Self(indexmap!{
                                "float".to_string() => encrypted_leaf("ENC[AES256_GCM,data:/MTg0fCennyN8g==,iv:+/8+Ljm+cls7BbDYZnlg6NVFkrkw4GkEfWU2aGW57qE=,tag:26uMp2JmVAckySIaL2BLCg==,type:float]")
                            })),
                        ]),
                    })
                ),
                "booleans".to_string() => RopsTree::Sequence(vec![
                    encrypted_leaf("ENC[AES256_GCM,data:bCdz2A==,iv:8kD+h1jClyVHBj9o2WZuAkjk+uD6A2lgNpcGljpQEhk=,tag:u3/fktl5HfFrVLERVvLRGw==,type:bool]"),
                    encrypted_leaf("ENC[AES256_GCM,data:SgBh7wY=,iv:0s9Q9pQWbsZm2yHsmFalCzX0IqNb6ZqeY6QQYCWc+qU=,tag:OZb76BWCKbDLbcil4c8fYA==,type:bool]")
                ]),
                "escape_unencrypted".to_string() => RopsTree::Leaf(RopsMapEncryptedLeaf::Escaped(RopsValue::String("plaintext".to_string())))
            })
        }
    }

    impl MockOtherTestUtil for RopsMap<EncryptedMap<AES256GCM>> {
        fn mock_other() -> Self {
            Self(indexmap! {
                "mumbo".to_string() => encrypted_leaf("ENC[AES256_GCM,data:wDdb+6I=,iv:WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=,tag:nrMkveJj0FpDVLdKM5xn7g==,type:str]")
            })
        }
    }

    fn encrypted_leaf(encrypted_value_str: &str) -> RopsTree<EncryptedMap<AES256GCM>> {
        RopsTree::Leaf(RopsMapEncryptedLeaf::Encrypted(encrypted_value_str.parse().unwrap()))
    }
}
