use aes_gcm::{aes::Aes256, AeadCore, AeadInPlace, Aes256Gcm, AesGcm, Key, KeyInit};
use generic_array::typenum::U32;

use crate::*;

#[derive(Debug, PartialEq)]
pub struct AES256GCM;

impl AES256GCM {
    pub fn cipher(data_key: &DataKey) -> AesGcm<Aes256, <Self as AeadCipher>::NonceSize, <Self as AeadCipher>::AuthorizationTagSize> {
        AesGcm::new(Key::<Aes256Gcm>::from_slice(data_key.as_ref()))
    }
}

impl AeadCipher for AES256GCM {
    const NAME: &'static str = "AES256_GCM";

    type NonceSize = U32;

    type AuthorizationTagSize = <Aes256Gcm as AeadCore>::TagSize;

    type Error = aes_gcm::Error;

    fn encrypt(
        nonce: &Nonce<Self::NonceSize>,
        data_key: &DataKey,
        in_place_buffer: &mut [u8],
        associated_data: &[u8],
    ) -> Result<AuthorizationTag<Self>, Self::Error> {
        Self::cipher(data_key)
            .encrypt_in_place_detached(nonce.as_ref().into(), associated_data, in_place_buffer)
            .map(Into::into)
    }

    fn decrypt(
        nonce: &Nonce<Self::NonceSize>,
        data_key: &DataKey,
        in_place_buffer: &mut [u8],
        associated_data: &[u8],
        authorization_tag: &AuthorizationTag<Self>,
    ) -> Result<(), Self::Error> {
        Self::cipher(data_key).decrypt_in_place_detached(
            nonce.as_ref().into(),
            associated_data,
            in_place_buffer,
            authorization_tag.as_ref(),
        )
    }
}
