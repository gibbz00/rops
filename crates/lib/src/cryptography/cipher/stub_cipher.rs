use generic_array::typenum::U32;

use crate::*;

#[derive(Debug, PartialEq)]
pub struct StubCipher;

impl AeadCipher for StubCipher {
    const NAME: &'static str = "STUB";

    type NonceSize = U32;
    type AuthorizationTagSize = U32;
    type EncryptError = ();

    fn encrypt(
        _nonce: &Nonce<Self::NonceSize>,
        _data_key: &DataKey,
        _in_place_buffer: &mut [u8],
        _associated_data: &[u8],
    ) -> Result<AuthorizationTag<Self>, Self::EncryptError> {
        unimplemented!()
    }
}
