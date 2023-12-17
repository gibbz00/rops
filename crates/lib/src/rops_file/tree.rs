use crate::*;

#[derive(Debug, PartialEq)]
pub enum RopsTree<S: RopsFileState> {
    Sequence(Vec<RopsTree<S>>),
    Map(indexmap::IndexMap<String, RopsTree<S>>),
    Null,
    Leaf(S::RopsTreeLeaf),
}

// IMPROVEMENT: Might be worth splitting distinguishing decrypted and
// encrypted map to tree errors by separating then into two enums.
#[derive(Debug, thiserror::Error)]
pub enum MapToTreeError {
    #[error("only string keys are supported, found: {0}")]
    NonStringKey(String),
    #[error("integer out of range, allowed values must fit inside an i64, found: {0}")]
    IntegerOutOfRange(u64),
    #[error("unable to parse encrypted value components: {0}")]
    EncryptedRopsValue(#[from] EncryptedRopsValueFromStrError),
    // TEMP: Deprecate once partial encryption feature arrives.
    #[error("invalid valid for an encrypted file")]
    InvalidValueForEncrypted(String),
}

mod decrypt {
    use std::collections::HashMap;

    use super::*;

    type SavedNonces<'a> = HashMap<(KeyPath, &'a RopsValue), Nonce>;

    impl<C: Cipher> RopsTree<Encrypted<C>> {
        pub fn decrypt(self, _data_key: &DataKey) -> Result<(RopsTree<Decrypted>, SavedNonces), C::Error> {
            todo!()
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use indexmap::indexmap;

    use super::*;

    impl MockTestUtil for RopsTree<Decrypted> {
        fn mock() -> Self {
            Self::Map(indexmap! {
                "hello".to_string() => RopsTree::Leaf(RopsValue::String("world!".to_string())),
                "nested_map".to_string() => RopsTree::Map(indexmap! {
                        "null_key".to_string() => RopsTree::Null,
                        "array".to_string() => RopsTree::Sequence(vec![
                            RopsTree::Leaf(RopsValue::String("string".to_string())),
                            RopsTree::Map(indexmap! {
                                "nested_map_in_array".to_string() => RopsTree::Map(indexmap!{
                                    "integer".to_string() => RopsTree::Leaf(RopsValue::Integer(1234))
                                }),
                            }),
                            RopsTree::Map(indexmap!{
                                "float".to_string() => RopsTree::Leaf(RopsValue::Float(1234.56789))
                            }),
                        ]),
                    }
                ),
                "booleans".to_string() => RopsTree::Sequence(vec![
                    RopsTree::Leaf(RopsValue::Boolean(true)),
                    RopsTree::Leaf(RopsValue::Boolean(false))
                ])
            })
        }
    }

    #[cfg(feature = "aes-gcm")]
    impl MockTestUtil for RopsTree<Encrypted<AES256GCM>> {
        fn mock() -> Self {
            return Self::Map(indexmap! {
                "hello".to_string() => leaf("ENC[AES256_GCM,data:3S1E9am/,iv:WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=,tag:nQUDkuh0OR1cjR5hGC5jOw==,type:str]"),
                "nested_map".to_string() => RopsTree::Map(indexmap! {
                        "null_key".to_string() => RopsTree::Null,
                        "array".to_string() => RopsTree::Sequence(vec![
                            leaf("ENC[AES256_GCM,data:ANbeNrGp,iv:PRWGCPdOttPr5dlzT9te7WWCZ90J7+CvfY1vp60aADM=,tag:PvSLx4pLT5zRKOU0df8Xlg==,type:str]"),
                            RopsTree::Map(indexmap! {
                                "nested_map_in_array".to_string() => RopsTree::Map(indexmap!{
                                    "integer".to_string() => leaf("ENC[AES256_GCM,data:qTW5qw==,iv:ugMxvR8YPwDgn2MbBpDX0lpCqzJY3GerhbA5jEKUbwE=,tag:d8utfA76C4XPzJyDfgE4Pw==,type:int]")
                                }),
                            }),
                            RopsTree::Map(indexmap!{
                                "float".to_string() => leaf("ENC[AES256_GCM,data:/MTg0fCennyN8g==,iv:+/8+Ljm+cls7BbDYZnlg6NVFkrkw4GkEfWU2aGW57qE=,tag:26uMp2JmVAckySIaL2BLCg==,type:float]")
                            }),
                        ]),
                    }
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
