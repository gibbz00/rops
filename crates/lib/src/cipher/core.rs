use std::fmt::Debug;

use generic_array::ArrayLength;

use crate::*;

pub trait AeadCipher: Sized {
    const NAME: &'static str;

    type InitialValueSize: ArrayLength<u8> + Debug + PartialEq;

    type AuthorizationTagSize: ArrayLength<u8> + Debug + PartialEq;

    type DecryptionError;

    fn encrypt(
        initial_value: &InitialValue<Self::InitialValueSize>,
        data_key: &DataKey,
        associated_data: &[u8],
        output_buffer: &mut [u8],
    ) -> Result<AuthorizationTag<Self>, Self::DecryptionError>;
}
