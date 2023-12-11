use std::borrow::Cow;

use crate::*;

pub enum RopsValue {
    String(String),
    Boolean(bool),
    Integer(i32),
    Float(f64),
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

impl RopsValue {
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

    pub fn encrypt<C: AeadCipher>(
        &self,
        nonce: Nonce<C::NonceSize>,
        data_key: &DataKey,
        key_path: &str,
    ) -> Result<EncryptedRopsValue<C>, C::DecryptionError> {
        let mut in_place_buffer = self.as_bytes().to_vec();

        let authorization_tag = C::encrypt(&nonce, data_key, &mut in_place_buffer, key_path.as_bytes())?;

        Ok(EncryptedRopsValue {
            data: in_place_buffer.into(),
            authorization_tag,
            nonce,
            value_variant: self.into(),
        })
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

        #[test]
        fn encrypts_string_value() {
            assert_eq!(
                EncryptedRopsValue::mock(),
                RopsValue::mock()
                    .encrypt(MockTestUtil::mock(), &MockTestUtil::mock(), "hello:")
                    .unwrap()
            );
        }

        #[test]
        fn encrypts_boolean_true_value() {
            assert_eq!(
                "ENC[AES256_GCM,data:0wTZfQ==,iv:BpeJcPsLzvRLyGOAyA/mM3nGhg3zIFEcpyfB5jJbul8=,tag:+OGu7RruuYSwMWZa1yWrqA==,type:bool]"
                    .parse::<EncryptedRopsValue<AES256GCM>>()
                    .unwrap(),
                RopsValue::Boolean(true)
                    .encrypt(
                        "BpeJcPsLzvRLyGOAyA/mM3nGhg3zIFEcpyfB5jJbul8=".parse().unwrap(),
                        &MockTestUtil::mock(),
                        "example_booleans:"
                    )
                    .unwrap()
            );
        }

        #[test]
        fn encrypts_boolean_false_value() {
            assert_eq!(
                "ENC[AES256_GCM,data:4EgnUYs=,iv:g0r5WzzWt/Ln25wlEescMgrTg88JTJhlOdI0g/xVahk=,tag:zhv8xxJULpXIWdzm5+C0FA==,type:bool]"
                    .parse::<EncryptedRopsValue<AES256GCM>>()
                    .unwrap(),
                RopsValue::Boolean(false)
                    .encrypt(
                        "g0r5WzzWt/Ln25wlEescMgrTg88JTJhlOdI0g/xVahk=".parse().unwrap(),
                        &MockTestUtil::mock(),
                        "example_booleans:"
                    )
                    .unwrap()
            );
        }

        #[test]
        fn encrypts_integer_value() {
            assert_eq!(
                "ENC[AES256_GCM,data:lDJCrw==,iv:P8EXxNCPeYp5VBL0mCAxjQjGtvywbBFoQKWye2IK1Gc=,tag:56HP04AzkYfj+pmYIbijSA==,type:int]"
                    .parse::<EncryptedRopsValue<AES256GCM>>()
                    .unwrap(),
                RopsValue::Integer(1234)
                    .encrypt(
                        "P8EXxNCPeYp5VBL0mCAxjQjGtvywbBFoQKWye2IK1Gc=".parse().unwrap(),
                        &MockTestUtil::mock(),
                        "example_integer:"
                    )
                    .unwrap()
            );
        }
        #[test]
        fn encrypts_float_value() {
            assert_eq!(
                "ENC[AES256_GCM,data:fglPlT+e9ACWrA==,iv:pefOFnMThS6qICGrLuai+rSBtrmliGWdqJrXzcl2qAo=,tag:tHVQiwreFZurqiroPCIXHw==,type:float]"
                    .parse::<EncryptedRopsValue<AES256GCM>>()
                    .unwrap(),
                RopsValue::Float(1234.56789)
                    .encrypt(
                        "pefOFnMThS6qICGrLuai+rSBtrmliGWdqJrXzcl2qAo=".parse().unwrap(),
                        &MockTestUtil::mock(),
                        "example_float:"
                    )
                    .unwrap()
            );
        }
    }
}
