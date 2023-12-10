use aes_gcm::Aes256Gcm;

use crate::*;

#[derive(Debug, PartialEq)]
pub struct AES256GCM;

impl Cipher for AES256GCM {
    type AuthorizationTagSize = <Aes256Gcm as aes_gcm::AeadCore>::TagSize;
    const NAME: &'static str = "AES256_GCM";
}
