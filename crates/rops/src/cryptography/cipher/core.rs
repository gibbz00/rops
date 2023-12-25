use std::fmt::Debug;

use generic_array::ArrayLength;

use crate::*;

pub trait Cipher: Sized + private::SealedCipher {
    const NAME: &'static str;

    type NonceSize: ArrayLength<u8> + Debug + PartialEq;

    type AuthorizationTagSize: ArrayLength<u8> + Debug + PartialEq;

    type Error: std::error::Error + Send + Sync + 'static;

    fn encrypt(
        nonce: &Nonce<Self::NonceSize>,
        data_key: &DataKey,
        in_place_buffer: &mut [u8],
        associated_data: &[u8],
    ) -> Result<AuthorizationTag<Self>, Self::Error>;

    fn decrypt(
        nonce: &Nonce<Self::NonceSize>,
        data_key: &DataKey,
        in_place_buffer: &mut [u8],
        associated_data: &[u8],
        authorization_tag: &AuthorizationTag<Self>,
    ) -> Result<(), Self::Error>;
}

mod private {
    use super::*;

    pub trait SealedCipher {}

    #[cfg(feature = "test-utils")]
    impl SealedCipher for StubCipher {}

    #[cfg(feature = "aes-gcm")]
    impl SealedCipher for AES256GCM {}
}
