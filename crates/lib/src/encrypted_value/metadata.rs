use crate::*;

#[derive(Debug, PartialEq)]
pub struct EncryptedValueMetaData<C: Cipher> {
    pub authorization_tag: AuthorizationTag<C>,
    pub initial_value: InitialValue,
    pub value_type: ValueVariant,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<C: Cipher> MockTestUtil for EncryptedValueMetaData<C>
    where
        AuthorizationTag<C>: MockTestUtil,
    {
        fn mock() -> Self {
            Self {
                authorization_tag: MockTestUtil::mock(),
                initial_value: MockTestUtil::mock(),
                value_type: ValueVariant::String,
            }
        }
    }
}
