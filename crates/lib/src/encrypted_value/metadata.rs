use crate::*;

#[derive(Debug, PartialEq)]
pub struct EncryptedValueMetaData {
    pub cipher_variant: CipherVariant,
    pub initial_value: InitialValue,
    pub value_type: ValueType,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for EncryptedValueMetaData {
        fn mock() -> Self {
            Self {
                cipher_variant: CipherVariant::AES256GCM,
                initial_value: MockTestUtil::mock(),
                value_type: ValueType::String,
            }
        }
    }
}
