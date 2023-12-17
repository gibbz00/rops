use std::borrow::Cow;

use crate::*;

#[derive(Debug, PartialEq)]
pub enum RopsValue {
    String(String),
    Boolean(bool),
    Integer(i64),
    Float(f64),
}

impl RopsValue {
    const BOOLEAN_TRUE_BYTES: &'static [u8] = b"True";
    const BOOLEAN_FALSE_BYTES: &'static [u8] = b"False";

    pub fn encrypt<C: AeadCipher>(
        &self,
        nonce: Nonce<C::NonceSize>,
        data_key: &DataKey,
        key_path: &KeyPath,
    ) -> Result<EncryptedRopsValue<C>, C::Error> {
        let mut in_place_buffer = self.as_bytes().to_vec();

        let authorization_tag = C::encrypt(&nonce, data_key, &mut in_place_buffer, key_path.as_bytes())?;

        Ok(EncryptedRopsValue {
            data: in_place_buffer.into(),
            authorization_tag,
            nonce,
            value_variant: self.into(),
        })
    }

    pub fn as_bytes(&self) -> Cow<'_, [u8]> {
        match self {
            RopsValue::String(string) => Cow::Borrowed(string.as_bytes()),
            RopsValue::Boolean(boolean) => Cow::Borrowed(match boolean {
                true => Self::BOOLEAN_TRUE_BYTES,
                false => Self::BOOLEAN_FALSE_BYTES,
            }),
            RopsValue::Integer(integer) => Cow::Owned(integer.to_string().into_bytes()),
            RopsValue::Float(float) => Cow::Owned(float.to_string().into_bytes()),
        }
    }

    pub fn from_bytes(bytes: Vec<u8>, variant: RopsValueVariant) -> Result<Self, RopsValueFromBytesError> {
        Ok(match variant {
            RopsValueVariant::String => Self::String(std::str::from_utf8(&bytes)?.to_string()),
            RopsValueVariant::Boolean => Self::Boolean(match bytes.as_slice() {
                Self::BOOLEAN_TRUE_BYTES => true,
                Self::BOOLEAN_FALSE_BYTES => false,
                _ => return Err(RopsValueFromBytesError::Boolean(bytes)),
            }),
            RopsValueVariant::Integer => Self::Integer(std::str::from_utf8(&bytes)?.parse()?),
            RopsValueVariant::Float => Self::Float(std::str::from_utf8(&bytes)?.parse()?),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RopsValueFromBytesError {
    #[error("unable to validate bytes as UTF-8: {0}")]
    String(#[from] std::str::Utf8Error),
    #[error("invalid byte representation for boolean values: {0:?}")]
    Boolean(Vec<u8>),
    #[error("integer parse error: {0}")]
    Integer(#[from] std::num::ParseIntError),
    #[error("float parse error: {0}")]
    Float(#[from] std::num::ParseFloatError),
}

impl From<&RopsValue> for RopsValueVariant {
    fn from(value: &RopsValue) -> Self {
        match value {
            RopsValue::String(_) => RopsValueVariant::String,
            RopsValue::Boolean(_) => RopsValueVariant::Boolean,
            RopsValue::Integer(_) => RopsValueVariant::Integer,
            RopsValue::Float(_) => RopsValueVariant::Float,
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for RopsValue {
        fn mock() -> Self {
            Self::String("world!".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use crate::*;

        fn assert_encrypts_value(expected_encrypted_value_str: &str, key_path: &str, rops_value: RopsValue) {
            let key_path = KeyPath::from(key_path.to_string());
            let expected_encrypted_value = expected_encrypted_value_str.parse::<EncryptedRopsValue<AES256GCM>>().unwrap();
            assert_eq!(
                expected_encrypted_value,
                rops_value
                    .encrypt(expected_encrypted_value.nonce.clone(), &MockTestUtil::mock(), &key_path)
                    .unwrap()
            )
        }

        #[test]
        fn encrypts_string_value() {
            assert_encrypts_value(
                "ENC[AES256_GCM,data:3S1E9am/,iv:WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=,tag:nQUDkuh0OR1cjR5hGC5jOw==,type:str]",
                "hello:",
                RopsValue::String("world!".to_string()),
            );
        }

        #[test]
        fn encrypts_boolean_true_value() {
            assert_encrypts_value(
                "ENC[AES256_GCM,data:0wTZfQ==,iv:BpeJcPsLzvRLyGOAyA/mM3nGhg3zIFEcpyfB5jJbul8=,tag:+OGu7RruuYSwMWZa1yWrqA==,type:bool]",
                "example_booleans:",
                RopsValue::Boolean(true),
            );
        }

        #[test]
        fn encrypts_boolean_false_value() {
            assert_encrypts_value(
                "ENC[AES256_GCM,data:4EgnUYs=,iv:g0r5WzzWt/Ln25wlEescMgrTg88JTJhlOdI0g/xVahk=,tag:zhv8xxJULpXIWdzm5+C0FA==,type:bool]",
                "example_booleans:",
                RopsValue::Boolean(false),
            );
        }

        #[test]
        fn encrypts_integer_value() {
            assert_encrypts_value(
                "ENC[AES256_GCM,data:lDJCrw==,iv:P8EXxNCPeYp5VBL0mCAxjQjGtvywbBFoQKWye2IK1Gc=,tag:56HP04AzkYfj+pmYIbijSA==,type:int]",
                "example_integer:",
                RopsValue::Integer(1234),
            );
        }
        #[test]
        fn encrypts_float_value() {
            assert_encrypts_value(
                "ENC[AES256_GCM,data:fglPlT+e9ACWrA==,iv:pefOFnMThS6qICGrLuai+rSBtrmliGWdqJrXzcl2qAo=,tag:tHVQiwreFZurqiroPCIXHw==,type:float]",
                "example_float:",
                RopsValue::Float(1234.56789),
            );
        }
    }
}
