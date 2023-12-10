use crate::*;

#[derive(Debug, PartialEq)]
pub struct EncryptedValueMetaData<C: AeadCipher> {
    pub authorization_tag: AuthorizationTag<C>,
    pub initial_value: InitialValue<C::InitialValueSize>,
    pub value_variant: RopsValueVariant,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<C: AeadCipher> MockTestUtil for EncryptedValueMetaData<C>
    where
        AuthorizationTag<C>: MockTestUtil,
    {
        fn mock() -> Self {
            Self {
                authorization_tag: MockTestUtil::mock(),
                initial_value: MockTestUtil::mock(),
                value_variant: RopsValueVariant::String,
            }
        }
    }
}
