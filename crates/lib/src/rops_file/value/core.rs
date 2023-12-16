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
    pub fn encrypt<C: AeadCipher>(
        &self,
        nonce: Nonce<C::NonceSize>,
        data_key: &DataKey,
        key_path: &str,
    ) -> Result<EncryptedRopsValue<C>, C::EncryptError> {
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
                true => b"True",
                false => b"False",
            }),
            RopsValue::Integer(integer) => Cow::Owned(integer.to_string().into_bytes()),
            RopsValue::Float(float) => Cow::Owned(float.to_string().into_bytes()),
        }
    }
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use crate::*;

        fn assert_encrypts_value(expected_encrypted_value_str: &str, key_path: &str, rops_value: RopsValue) {
            let expected_encrypted_value = expected_encrypted_value_str.parse::<EncryptedRopsValue<AES256GCM>>().unwrap();
            assert_eq!(
                expected_encrypted_value,
                rops_value
                    .encrypt(expected_encrypted_value.nonce.clone(), &MockTestUtil::mock(), key_path)
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
