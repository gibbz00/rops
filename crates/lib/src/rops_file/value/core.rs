use crate::*;

pub enum RopsValue {
    String(String),
    Boolean(bool),
}

impl From<&RopsValue> for RopsValueVariant {
    fn from(value: &RopsValue) -> Self {
        match value {
            RopsValue::String(_) => RopsValueVariant::String,
            RopsValue::Boolean(_) => RopsValueVariant::Boolean,
        }
    }
}

impl RopsValue {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            RopsValue::String(string) => string.as_bytes(),
            RopsValue::Boolean(boolean) => match boolean {
                true => b"True",
                false => b"False",
            },
            // ...etc
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
    }
}
