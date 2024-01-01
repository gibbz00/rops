use std::io::{Read, Write};

use age::{
    armor::{ArmoredReader, ArmoredWriter, Format},
    Decryptor,
};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct AgeIntegration;

impl AgeIntegration {
    const APPROX_MAX_ARMORED_DATA_KEY_LENGTH: usize = 400;
}

impl Integration for AgeIntegration {
    const NAME: &'static str = "age";
    type KeyId = age::x25519::Recipient;
    type PrivateKey = age::x25519::Identity;
    type Config = AgeConfig;

    fn parse_key_id(key_id_str: &str) -> IntegrationResult<Self::KeyId> {
        key_id_str
            .parse()
            .map_err(|err: &str| IntegrationError::KeyIdParsing(anyhow::anyhow!(err)))
    }

    fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey> {
        private_key_str
            .as_ref()
            .parse()
            .map_err(|err: &str| IntegrationError::PrivateKeyParsing(anyhow::anyhow!(err)))
    }

    fn encrypt_data_key(key_id: &Self::KeyId, data_key: &DataKey) -> IntegrationResult<String> {
        let unarmored_buffer = {
            // IMPROVEMENT: avoid vec box allocation
            let encryptor =
                age::Encryptor::with_recipients(vec![Box::new(key_id.clone())]).expect("provided recipients should be non-empty");

            let mut unarmored_encypted_buffer = Vec::with_capacity(DataKey::byte_size());
            let mut encryption_writer = encryptor.wrap_output(&mut unarmored_encypted_buffer)?;
            encryption_writer.write_all(data_key.as_ref())?;
            encryption_writer.finish()?;
            unarmored_encypted_buffer
        };

        let mut armored_buffer = Vec::with_capacity(Self::APPROX_MAX_ARMORED_DATA_KEY_LENGTH);
        let mut armored_writer = ArmoredWriter::wrap_output(&mut armored_buffer, Format::AsciiArmor)?;
        armored_writer.write_all(&unarmored_buffer)?;
        armored_writer.finish()?;

        Ok(String::from_utf8(armored_buffer)?)
    }

    fn decrypt_data_key(key_id: &Self::KeyId, encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>> {
        let private_keys = Self::retrieve_private_keys()?;

        let Some(matched_private_key) = private_keys.into_iter().find(|private_key| &private_key.to_public() == key_id) else {
            return Ok(None);
        };

        let mut unarmored_encrypted_buffer = Vec::with_capacity(Self::APPROX_MAX_ARMORED_DATA_KEY_LENGTH);

        ArmoredReader::new(encrypted_data_key.as_bytes()).read_to_end(&mut unarmored_encrypted_buffer)?;

        let decryptor = match Decryptor::new(unarmored_encrypted_buffer.as_slice())? {
            Decryptor::Recipients(decryptor) => decryptor,
            Decryptor::Passphrase(_) => panic!("encryption should have used recipients, not passphrases"),
        };

        let mut decrypted_data_key_buffer = DataKey::empty();
        let mut reader = decryptor.decrypt(std::iter::once(&matched_private_key as &dyn age::Identity))?;
        reader.read_exact(decrypted_data_key_buffer.as_mut())?;

        Ok(Some(decrypted_data_key_buffer))
    }

    fn select_metadata_units_field(integration_metadata: &mut IntegrationMetadata) -> &mut Vec<IntegrationMetadataUnit<Self>> {
        &mut integration_metadata.age
    }
}

mod error {
    use super::*;

    impl From<age::EncryptError> for IntegrationError {
        fn from(encrypt_error: age::EncryptError) -> Self {
            Self::Encryption(encrypt_error.into())
        }
    }

    impl From<age::DecryptError> for IntegrationError {
        fn from(decrypt_error: age::DecryptError) -> Self {
            Self::Decryption(decrypt_error.into())
        }
    }
}

mod key_id {
    use super::*;

    impl IntegrationKeyId<AgeIntegration> for age::x25519::Recipient {
        fn append_to_builder<F: FileFormat>(self, rops_file_builder: &mut RopsFileBuilder<F>) {
            rops_file_builder.age_key_ids.push(self)
        }
    }

    #[cfg(feature = "test-utils")]
    mod mock {
        use super::*;

        impl MockDisplayTestUtil for age::x25519::Recipient {
            fn mock_display() -> String {
                "age1se5ghfycr4n8kcwc3qwf234ymvmr2lex2a99wh8gpfx97glwt9hqch4569".to_string()
            }
        }

        impl MockTestUtil for age::x25519::Recipient {
            fn mock() -> Self {
                Self::mock_display().parse().unwrap()
            }
        }
    }
}

pub use config::AgeConfig;
mod config {
    use serde::{Deserialize, Serialize};
    use serde_with::{serde_as, DisplayFromStr};

    use crate::*;

    #[serde_as]
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct AgeConfig {
        #[serde_as(as = "DisplayFromStr")]
        #[serde(rename = "recipient")]
        pub key_id: <AgeIntegration as Integration>::KeyId,
    }

    impl IntegrationConfig<AgeIntegration> for AgeConfig {
        const INCLUDE_DATA_KEY_CREATED_AT: bool = false;

        fn new(key_id: <AgeIntegration as Integration>::KeyId) -> Self {
            Self { key_id }
        }

        fn key_id(&self) -> &<AgeIntegration as Integration>::KeyId {
            &self.key_id
        }
    }

    #[cfg(feature = "test-utils")]
    mod mock {
        use super::*;

        impl MockTestUtil for AgeConfig {
            fn mock() -> Self {
                Self {
                    key_id: MockTestUtil::mock(),
                }
            }
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl IntegrationTestUtils for AgeIntegration {
        fn mock_private_key_str() -> impl AsRef<str> {
            "AGE-SECRET-KEY-1EQUCGFZH8UZKSZ0Z5N5T234YRNDT4U9H7QNYXWRRNJYDDVXE6FWSCPGNJ7"
        }

        fn mock_encrypted_data_key_str() -> &'static str {
            indoc::indoc! {"
                -----BEGIN AGE ENCRYPTED FILE-----
                YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBKeE9VRHJpNmc4Z1NFeDd6
                L3cybjRHblYvaFUxbk9JZDZ4RFdENGpiNmhZCnZCRXRNSlRZeno0SDlJWXdhT0xl
                Y1BlMzcyYUdVWFJ6WEVMTlRRaDRGbFUKLS0tIGc0V3gzU043MzBUd01BVTVKTEwr
                azRyUldHUXo0cTV2YlZWa2pwcWFweGcKQdFW597WOM0bYfycoA2A0JxjKlrka+lc
                MLuTri7QMM+g8yXcjneEGxjobGIqnvARlzDwcnFMxBoZ5/KRjMipXA==
                -----END AGE ENCRYPTED FILE-----
            "}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    generate_integration_test_suite!(AgeIntegration);
}
