use std::fmt::{Display, Formatter};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct EncryptedValue<C: AeadCipher> {
    pub data: EncryptedValueData,
    pub authorization_tag: AuthorizationTag<C>,
    pub initial_value: InitialValue<C::InitialValueSize>,
    pub value_variant: RopsValueVariant,
}

impl<C: AeadCipher> Display for EncryptedValue<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ENC[{},data:{},iv:{},tag:{},type:{}]",
            C::NAME,
            self.data.encode_base64(),
            self.initial_value.encode_base64(),
            self.authorization_tag.encode_base64(),
            self.value_variant.as_ref(),
        )
    }
}

pub use parser::EncryptedValueFromStrError;
mod parser {
    use std::str::FromStr;

    use super::*;

    #[derive(Debug, thiserror::Error)]
    pub enum EncryptedValueFromStrError {
        #[error("missing {0}")]
        Missing(&'static str),
        #[error("invalid cipher: {0}, expected: {1}")]
        InvalidCipher(String, &'static str),
        #[error("unable to parse value type: {0}")]
        ValueVariantFromStr(String),
        #[error(transparent)]
        Base64Decode(#[from] Base64DecodeError),
    }

    impl<C: AeadCipher> FromStr for EncryptedValue<C> {
        type Err = EncryptedValueFromStrError;

        fn from_str(input: &str) -> Result<Self, Self::Err> {
            use EncryptedValueFromStrError::*;

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

            let initial_value = encrypted_value_components
                .next()
                .and_then(|next_component| next_component.strip_prefix("iv:"))
                .ok_or(Missing("'iv' (initial value) key-value pair"))
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
                initial_value,
                value_variant,
            })
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<C: AeadCipher> MockTestUtil for EncryptedValue<C>
    where
        AuthorizationTag<C>: MockTestUtil,
        InitialValue<C::InitialValueSize>: MockTestUtil,
    {
        fn mock() -> Self {
            Self {
                data: MockTestUtil::mock(),
                authorization_tag: MockTestUtil::mock(),
                initial_value: MockTestUtil::mock(),
                value_variant: RopsValueVariant::String,
            }
        }
    }

    impl<C: AeadCipher> MockDisplayTestUtil for EncryptedValue<C>
    where
        AuthorizationTag<C>: MockDisplayTestUtil,
    {
        fn mock_display() -> String {
            format!(
                "ENC[{},data:{},iv:{},tag:{},type:str]",
                C::NAME,
                EncryptedValueData::mock_display(),
                InitialValue::mock_display(),
                AuthorizationTag::mock_display()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "aes-gcm")]
    mod aes {
        use crate::*;

        #[test]
        fn displays_value_encryption_content() {
            DisplayTestUtils::assert_display::<EncryptedValue<AES256GCM>>()
        }

        #[test]
        fn parses_value_encryption_content() {
            FromStrTestUtils::assert_parse::<EncryptedValue<AES256GCM>>()
        }
    }
}
