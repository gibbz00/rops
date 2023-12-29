use std::{convert::AsRef, future::Future, ops::Deref};

use anyhow::anyhow;
use aws_sdk_kms::{config::Credentials, primitives::Blob, Client, Config};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct AwsKmsIntegration;

impl Integration for AwsKmsIntegration {
    const NAME: &'static str = "aws_kms";
    type KeyId = AwsKeyId;
    type PrivateKey = AwsPrivateKey;
    type Config = AwsKmsConfig;

    fn parse_key_id(key_id_str: &str) -> IntegrationResult<Self::KeyId> {
        key_id_str
            .parse::<Self::KeyId>()
            .map_err(|err| IntegrationError::KeyIdParsing(err.into()))
    }

    fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey> {
        private_key_str.as_ref().parse()
    }

    // IMPROVEMENT: making these trait methods async might be worth looking once it becomes relevant
    // to call multiple integrations methods in parallel, rather than blocking the thread.

    fn encrypt_data_key(key_id: &Self::KeyId, data_key: &DataKey) -> IntegrationResult<String> {
        let encrypt_job = find_client(key_id)?
            .ok_or(IntegrationError::Encryption(anyhow!(
                "unable to find private keys for profile: {}",
                key_id.profile
            )))?
            .encrypt()
            .key_id(key_id.key_arn.key_id.deref())
            .plaintext(Blob::new(AsRef::<[u8]>::as_ref(data_key)));

        let encrypted_data_key_string = tokio_blocking(encrypt_job.send())
            .map_err(|error| IntegrationError::Encryption(error.into()))?
            .ciphertext_blob
            .expect("encryption response missing encrypted ciphertext")
            .encode_base64();

        Ok(encrypted_data_key_string)
    }

    fn decrypt_data_key(key_id: &Self::KeyId, encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>> {
        let mut decoded_bytes = Vec::with_capacity(DataKey::byte_size());
        decoded_bytes
            .decode_base64(encrypted_data_key)
            .map_err(|error| IntegrationError::Decryption(error.into()))?;

        let Some(decypt_client) = find_client(key_id)? else {
            return Ok(None);
        };

        let decrypt_job = decypt_client
            .decrypt()
            .key_id(key_id.key_arn.key_id.deref())
            .ciphertext_blob(Blob::new(decoded_bytes));

        let decrypted_bytes = tokio_blocking(decrypt_job.send())
            .map_err(|error| IntegrationError::Encryption(error.into()))?
            .plaintext
            .expect("decryption response missing decrypted plaintext")
            .into_inner();

        DataKey::try_from(decrypted_bytes)
            .map(Some)
            .map_err(|error| IntegrationError::Decryption(error.into()))
    }
}

fn tokio_blocking<O>(future: impl Future<Output = O>) -> O {
    tokio::runtime::Runtime::new().unwrap().block_on(future)
}

fn find_client(key_id: &AwsKeyId) -> IntegrationResult<Option<Client>> {
    let AwsKeyId { profile, key_arn } = key_id;

    let private_keys = AwsKmsIntegration::retrieve_private_keys()?;

    let Some(matching_private_key) = private_keys.into_iter().find(|key| &key.profile == profile) else {
        return Ok(None);
    };

    let config = Config::builder()
        .region(Some(key_arn.region.clone()))
        .credentials_provider(Credentials::new(
            matching_private_key.id,
            matching_private_key.secret,
            None,
            None,
            "rops",
        ))
        .build();

    Ok(Some(Client::from_conf(config)))
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl IntegrationTestUtils for AwsKmsIntegration {
        fn mock_key_id_str() -> impl AsRef<str> {
            AwsKeyId::mock_display()
        }

        fn mock_private_key_str() -> impl AsRef<str> {
            AwsPrivateKey::mock_display()
        }

        fn mock_encrypted_data_key_str() -> &'static str {
            "AQICAHiB4ozqhuEpHKVV+bXVXqxUTHq97nhkmOnQqSGLV5d0fAE5vjB9Tx8f5juCR3DPHGWZAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM9th1qt9YvZ2Vgu3TAgEQgDv7GInqnuJJno5ikZvMXQB7c4FLmqAqiuXAUP1NkYUn1OsdWuwdcH6nDKcn6GJ/ddBElY/Cd1tXqwrk7A=="
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    generate_integration_test_suite!(AwsKmsIntegration);
}
