use std::fmt::Debug;

use generic_array::ArrayLength;

use crate::*;

pub trait AeadCipher: Sized {
    const NAME: &'static str;

    type NonceSize: ArrayLength<u8> + Debug + PartialEq;

    type AuthorizationTagSize: ArrayLength<u8> + Debug + PartialEq;

    type DecryptionError;

    fn encrypt(
        nonce: &Nonce<Self::NonceSize>,
        data_key: &DataKey,
        in_place_buffer: &mut [u8],
        associated_data: &[u8],
    ) -> Result<AuthorizationTag<Self>, Self::DecryptionError>;
}
