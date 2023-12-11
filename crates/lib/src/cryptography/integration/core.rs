use std::fmt::Display;

use crate::*;

pub trait Integration {
    const NAME: &'static str;
    type PublicKey: Display;
    type PrivateKey;

    fn parse_public_key(public_key_str: &str) -> IntegrationResult<Self::PublicKey>;

    fn parse_private_key(private_key_str: &str) -> IntegrationResult<Self::PrivateKey>;

    fn encrypt_data_key(public_key: &Self::PublicKey, data_key: &DataKey) -> IntegrationResult<String>;

    fn decrypt_data_key(private_key: &Self::PrivateKey, encrypted_data_key: &str) -> IntegrationResult<DataKey>;
}
