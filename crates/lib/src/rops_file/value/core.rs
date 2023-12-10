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
    ) -> Result<EncryptedValue<C>, C::DecryptionError> {
        let input_bytes = self.as_bytes();
        let mut output_buffer = Vec::with_capacity(input_bytes.len());

        let authorization_tag = C::encrypt(&initial_value, data_key, input_bytes, &mut output_buffer)?;

        Ok(EncryptedValue {
            data: output_buffer.into(),
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
                RopsValue::mock().encrypt(MockTestUtil::mock(), &MockTestUtil::mock()).unwrap()
            );
        }
    }
}
