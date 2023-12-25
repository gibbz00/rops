use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct EncryptedRopsValue<C: Cipher> {
    pub data: EncryptedData,
    pub authorization_tag: AuthorizationTag<C>,
    pub nonce: Nonce<C::NonceSize>,
    pub value_variant: RopsValueVariant,
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptRopsValueError {
    #[error("encountered cipher error: {0}")]
    Cipher(anyhow::Error),
    #[error("unable convert value from decrypted bytes: {0}")]
    FromBytes(#[from] RopsValueFromBytesError),
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptedRopsValueFromStrError {
    #[error("missing {0}")]
    Missing(&'static str),
    #[error("invalid cipher: {0}, expected: {1}")]
    InvalidCipher(String, &'static str),
    #[error("unable to parse value type: {0}")]
    ValueVariantFromStr(String),
    #[error(transparent)]
    Base64Decode(#[from] Base64DecodeError),
}

impl<C: Cipher> EncryptedRopsValue<C> {
    pub fn decrypt(self, data_key: &DataKey, key_path: &KeyPath) -> Result<RopsValue, DecryptRopsValueError> {
        let mut in_place_buffer = self.data;

        C::decrypt(
            &self.nonce,
            data_key,
            in_place_buffer.as_mut(),
            key_path.as_ref(),
            &self.authorization_tag,
        )
        .map_err(|error| DecryptRopsValueError::Cipher(error.into()))?;

        RopsValue::from_bytes(in_place_buffer.into(), self.value_variant).map_err(Into::into)
    }
}

impl<C: Cipher> Display for EncryptedRopsValue<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ENC[{},data:{},iv:{},tag:{},type:{}]",
            C::NAME,
            self.data.encode_base64(),
            self.nonce.encode_base64(),
            self.authorization_tag.as_ref().encode_base64(),
            self.value_variant.as_ref(),
        )
    }
}

impl<C: Cipher> FromStr for EncryptedRopsValue<C> {
    type Err = EncryptedRopsValueFromStrError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        use EncryptedRopsValueFromStrError::*;

        let mut encrypted_value_components = input
            .strip_prefix("ENC")
            .ok_or(Missing("ENC prefix"))?
            .strip_prefix('[')
            .ok_or(Missing("opening ('[') bracket"))?
            .strip_suffix(']')
            .ok_or(Missing("closing (']') bracket"))?
            .split(',');

        let cipher_variant_str = encrypted_value_components.next().ok_or(Missing("cipher"))?;

        if cipher_variant_str != C::NAME {
            return Err(InvalidCipher(cipher_variant_str.to_string(), C::NAME));
        }

        let data = encrypted_value_components
            .next()
            .and_then(|next_component| next_component.strip_prefix("data:"))
            .ok_or(Missing("'data' key-value pair"))
            .and_then(|base64_str| base64_str.parse().map_err(Into::into))?;

        let nonce = encrypted_value_components
            .next()
            .and_then(|next_component| next_component.strip_prefix("iv:"))
            .ok_or(Missing("'iv' (initialization vector) key-value pair"))
            .and_then(|base64_str| base64_str.parse().map_err(Into::into))?;

        let authorization_tag = encrypted_value_components
            .next()
            .and_then(|next_component| next_component.strip_prefix("tag:"))
            .ok_or(Missing("'tag' (authorization tag) key-value pair"))
            .and_then(|base64_str| base64_str.parse().map_err(Into::into))?;

        let value_variant = encrypted_value_components
            .next()
            .and_then(|value_type_component| value_type_component.strip_prefix("type:"))
            .ok_or(Missing("'type' (value type) key-value pair"))
            .and_then(|variant_str| variant_str.parse().map_err(|_| ValueVariantFromStr(variant_str.to_string())))?;

        Ok(Self {
            data,
            authorization_tag,
            nonce,
            value_variant,
        })
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<C: Cipher> MockTestUtil for EncryptedRopsValue<C>
    where
        AuthorizationTag<C>: MockTestUtil,
        Nonce<C::NonceSize>: MockTestUtil,
    {
        fn mock() -> Self {
            Self {
                data: MockTestUtil::mock(),
                authorization_tag: MockTestUtil::mock(),
                nonce: MockTestUtil::mock(),
                value_variant: RopsValueVariant::String,
            }
        }
    }

    impl<C: Cipher> MockDisplayTestUtil for EncryptedRopsValue<C>
    where
        AuthorizationTag<C>: MockDisplayTestUtil,
    {
        fn mock_display() -> String {
            format!(
                "ENC[{},data:{},iv:{},tag:{},type:str]",
                C::NAME,
                EncryptedData::mock_display(),
                Nonce::mock_display(),
                AuthorizationTag::mock_display()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disallows_cipher_name_mismatch() {
        let parse_error = EncryptedRopsValue::<StubCipher>::mock_display()
            .replace(StubCipher::NAME, "gibberish")
            .parse::<EncryptedRopsValue<StubCipher>>()
            .unwrap_err();
        assert!(matches!(parse_error, EncryptedRopsValueFromStrError::InvalidCipher(_, _)))
    }

    #[cfg(feature = "aes-gcm")]
    mod aes {
        use super::*;

        #[test]
        fn displays_value() {
            DisplayTestUtils::assert_display::<EncryptedRopsValue<AES256GCM>>()
        }

        #[test]
        fn parses_value() {
            FromStrTestUtils::assert_parse::<EncryptedRopsValue<AES256GCM>>()
        }

        #[test]
        fn decrypts_value() {
            assert_eq!(
                RopsValue::mock(),
                EncryptedRopsValue::<AES256GCM>::mock()
                    .decrypt(&MockTestUtil::mock(), &MockTestUtil::mock())
                    .unwrap()
            )
        }
    }
}
