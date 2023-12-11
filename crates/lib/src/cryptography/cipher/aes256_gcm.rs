use aes_gcm::{aes::Aes256, *};
use generic_array::typenum::U32;

use crate::*;

#[derive(Debug, PartialEq)]
pub struct AES256GCM;

impl AeadCipher for AES256GCM {
    const NAME: &'static str = "AES256_GCM";

    type InitialValueSize = U32;

    type AuthorizationTagSize = <Aes256Gcm as AeadCore>::TagSize;

    type DecryptionError = aes_gcm::Error;

    fn encrypt(
        initial_value: &InitialValue<Self::InitialValueSize>,
        data_key: &DataKey,
        in_place_buffer: &mut [u8],
        associated_data: &[u8],
    ) -> Result<AuthorizationTag<Self>, Self::DecryptionError> {
        let cipher = AesGcm::<Aes256, Self::InitialValueSize>::new(Key::<Aes256Gcm>::from_slice(data_key.as_ref()));
        cipher
            .encrypt_in_place_detached(initial_value.as_ref().into(), associated_data, in_place_buffer)
            .map(Into::into)
    }
}
