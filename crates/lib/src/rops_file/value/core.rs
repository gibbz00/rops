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

#[cfg(test)]
mod tests {
    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use crate::*;

        #[test]
        fn encrypts_string_value() {
            assert_eq!(
                EncryptedValue::mock(),
                RopsValue::String("world!".to_string())
                    .encrypt(MockTestUtil::mock(), &MockTestUtil::mock(), "hello:")
                    .unwrap()
            );
        }
    }
}
