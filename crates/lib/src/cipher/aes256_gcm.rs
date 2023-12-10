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
        associated_data: &[u8],
        output_buffer: &mut [u8],
    ) -> Result<AuthorizationTag<Self>, Self::DecryptionError> {
        // U32 must be added to allowed tag sizes upstream
        let cipher =
            AesGcm::<Aes256, Self::AuthorizationTagSize, Self::InitialValueSize>::new(Key::<Aes256Gcm>::from_slice(data_key.as_ref()));
        cipher
            .encrypt_in_place_detached(initial_value.as_ref().into(), associated_data, output_buffer)
            .map(Into::into)
    }
}
