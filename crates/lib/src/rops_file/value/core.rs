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
        initial_value: InitialValue<C::InitialValueSize>,
        data_key: &DataKey,
        key_path: &str,
    ) -> Result<EncryptedValue<C>, C::DecryptionError> {
        let mut in_place_buffer = self.as_bytes().to_vec();

        let authorization_tag = C::encrypt(&initial_value, data_key, &mut in_place_buffer, key_path.as_bytes())?;

        Ok(EncryptedValue {
            data: in_place_buffer.into(),
            metadata: EncryptedValueMetaData {
                authorization_tag,
                initial_value,
                value_variant: self.into(),
            },
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
                EncryptedValue::mock(),
                RopsValue::mock()
                    .encrypt(MockTestUtil::mock(), &MockTestUtil::mock(), "hello:")
                    .unwrap()
            );
        }

        #[test]
        fn encrypts_boolean_true_value() {
            let mut initial_value = InitialValue::default();
            initial_value
                .as_mut()
                .decode_base64("BpeJcPsLzvRLyGOAyA/mM3nGhg3zIFEcpyfB5jJbul8=")
                .unwrap();

            assert_eq!(
                "ENC[AES256_GCM,data:0wTZfQ==,iv:BpeJcPsLzvRLyGOAyA/mM3nGhg3zIFEcpyfB5jJbul8=,tag:+OGu7RruuYSwMWZa1yWrqA==,type:bool]"
                    .parse::<EncryptedValue<AES256GCM>>()
                    .unwrap(),
                RopsValue::Boolean(true)
                    .encrypt(initial_value, &MockTestUtil::mock(), "example_booleans:")
                    .unwrap()
            );
        }

        #[test]
        fn encrypts_boolean_false_value() {
            let mut initial_value = InitialValue::default();
            initial_value
                .as_mut()
                .decode_base64("g0r5WzzWt/Ln25wlEescMgrTg88JTJhlOdI0g/xVahk=")
                .unwrap();

            assert_eq!(
                "ENC[AES256_GCM,data:4EgnUYs=,iv:g0r5WzzWt/Ln25wlEescMgrTg88JTJhlOdI0g/xVahk=,tag:zhv8xxJULpXIWdzm5+C0FA==,type:bool]"
                    .parse::<EncryptedValue<AES256GCM>>()
                    .unwrap(),
                RopsValue::Boolean(false)
                    .encrypt(initial_value, &MockTestUtil::mock(), "example_booleans:")
                    .unwrap()
            );
        }
    }
}
