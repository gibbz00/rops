use crate::*;

/// SSH keys used as age recipients.
///
/// `sops` stores SSH recipients in the very same `age` metadata field as native age
/// recipients, telling them apart by their `ssh-` prefix. Cryptography is left to the
/// `age` crate, this integration only takes care of the key handling that differs:
/// the private key retrieval, which for `sops` is also kept separate from age's.
#[derive(Debug, PartialEq)]
pub struct SshIntegration;

impl Integration for SshIntegration {
    const NAME: &'static str = "ssh";
    type KeyId = SshKeyId;
    type PrivateKey = SshPrivateKey;
    type Config = SshConfig;

    fn parse_key_id(key_id_str: &str) -> IntegrationResult<Self::KeyId> {
        key_id_str.parse().map_err(IntegrationError::KeyIdParsing)
    }

    fn parse_private_key(private_key_str: impl AsRef<str>) -> IntegrationResult<Self::PrivateKey> {
        private_key_str.as_ref().parse().map_err(IntegrationError::PrivateKeyParsing)
    }

    /// SSH private keys span several lines, so keys are separated by their PEM
    /// boundaries rather than by line breaks.
    fn parse_private_keys(private_keys_str: &str) -> IntegrationResult<Vec<Self::PrivateKey>> {
        let mut private_keys = Vec::new();
        let mut pem_block = String::new();

        for line in private_keys_str.lines().map(str::trim) {
            match pem_block.is_empty() {
                // Inside a PEM block, gather until its end boundary.
                false => {
                    pem_block.push_str(line);
                    pem_block.push('\n');

                    if line.starts_with(SshPrivateKey::PEM_END_PREFIX) {
                        private_keys.push(Self::parse_private_key(&pem_block)?);
                        pem_block.clear();
                    }
                }
                true => {
                    if line.starts_with(SshPrivateKey::PEM_BEGIN_PREFIX) {
                        pem_block.push_str(line);
                        pem_block.push('\n');
                    } else if !line.is_empty() {
                        // Not part of any PEM block, let parsing report what is wrong with it.
                        private_keys.push(Self::parse_private_key(line)?)
                    }
                }
            }
        }

        match pem_block.is_empty() {
            true => Ok(private_keys),
            false => Err(IntegrationError::PrivateKeyParsing(anyhow::anyhow!(
                "unterminated PEM block in private key input"
            ))),
        }
    }

    fn encrypt_data_key(key_id: &Self::KeyId, data_key: &DataKey) -> IntegrationResult<String> {
        super::age::encrypt_data_key(&key_id.0, data_key)
    }

    fn decrypt_data_key(key_id: &Self::KeyId, encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>> {
        let private_keys = Self::retrieve_private_keys()?;

        let Some(matched_private_key) = private_keys
            .iter()
            .find(|private_key| private_key.to_key_id().as_ref() == Some(key_id))
        else {
            return Ok(None);
        };

        super::age::decrypt_data_key(&matched_private_key.0, encrypted_data_key).map(Some)
    }

    fn select_metadata_units(integration_metadata: &mut IntegrationMetadata) -> &mut IntegrationMetadataUnits<Self> {
        &mut integration_metadata.ssh
    }
}

pub use key_id::SshKeyId;
mod key_id {
    use std::{
        fmt::{Display, Formatter, Result as FmtResult},
        hash::{Hash, Hasher},
        str::FromStr,
    };

    use crate::*;

    /// An SSH public key in the `authorized_keys` format: `ssh-ed25519 AAAAC3NzaC1...`.
    #[derive(Debug, Clone)]
    pub struct SshKeyId(pub(super) age::ssh::Recipient);

    impl FromStr for SshKeyId {
        type Err = anyhow::Error;

        fn from_str(key_id_str: &str) -> Result<Self, Self::Err> {
            key_id_str
                .trim()
                .parse()
                .map(Self)
                // age::ssh::ParseRecipientKeyError does not implement Display.
                .map_err(|error| anyhow::anyhow!("invalid SSH recipient: {:?}", error))
        }
    }

    impl Display for SshKeyId {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            self.0.fmt(f)
        }
    }

    // Manually implemented because age::ssh::Recipient derives neither PartialEq nor Hash;
    // its string representation is canonical.
    impl PartialEq for SshKeyId {
        fn eq(&self, other: &Self) -> bool {
            self.to_string() == other.to_string()
        }
    }

    impl Eq for SshKeyId {}

    impl Hash for SshKeyId {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.to_string().hash(state)
        }
    }

    impl AppendIntegrationKey<SshIntegration> for SshKeyId {
        fn append_to_metadata_builder(self, integration_metadata_builder: &mut IntegrationMetadataBuilder) {
            integration_metadata_builder.ssh_key_ids.push(self)
        }
    }

    #[cfg(feature = "test-utils")]
    mod mock {
        use super::*;

        impl MockDisplayTestUtil for SshKeyId {
            fn mock_display() -> String {
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpc2HFYyNPJNKDssZ1U6yVU68RKk7EbqtZyc+Y4bM11".to_string()
            }
        }

        impl MockTestUtil for SshKeyId {
            fn mock() -> Self {
                Self::mock_display().parse().unwrap()
            }
        }

        impl MockOtherTestUtil for SshKeyId {
            fn mock_other() -> Self {
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKDNyr8uEg1RqZYvUAXsrQ2Juv5OQ7WWejAaO4Heh2f7"
                    .parse()
                    .unwrap()
            }
        }
    }
}

pub use private_key::SshPrivateKey;
mod private_key {
    use std::str::FromStr;

    use crate::*;

    /// An unencrypted OpenSSH private key, PEM boundaries included.
    pub struct SshPrivateKey(pub(super) age::ssh::Identity);

    impl SshPrivateKey {
        pub(super) const PEM_BEGIN_PREFIX: &'static str = "-----BEGIN";
        pub(super) const PEM_END_PREFIX: &'static str = "-----END";

        /// Recipient this private key decrypts for, if it can be derived.
        pub(super) fn to_key_id(&self) -> Option<SshKeyId> {
            age::ssh::Recipient::try_from(self.0.clone()).ok().map(super::SshKeyId)
        }
    }

    impl FromStr for SshPrivateKey {
        type Err = anyhow::Error;

        fn from_str(private_key_str: &str) -> Result<Self, Self::Err> {
            match age::ssh::Identity::from_buffer(private_key_str.trim().as_bytes(), None)? {
                identity @ age::ssh::Identity::Unencrypted(_) => Ok(Self(identity)),
                // Rejected rather than skipped so as to not mistake a key which could
                // have been used for one which simply does not match.
                age::ssh::Identity::Encrypted(_) => Err(anyhow::anyhow!("passphrase protected SSH private keys are not supported")),
                age::ssh::Identity::Unsupported(_) => Err(anyhow::anyhow!("unsupported SSH private key type")),
            }
        }
    }
}

pub use config::SshConfig;
mod config {
    use serde::{Deserialize, Serialize};
    use serde_with::{serde_as, DisplayFromStr};

    use crate::*;

    #[serde_as]
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SshConfig {
        #[serde_as(as = "DisplayFromStr")]
        #[serde(rename = "recipient")]
        pub key_id: SshKeyId,
    }

    impl IntegrationConfig<SshIntegration> for SshConfig {
        const INCLUDE_DATA_KEY_CREATED_AT: bool = false;

        fn new(key_id: SshKeyId) -> Self {
            Self { key_id }
        }

        fn key_id(&self) -> &SshKeyId {
            &self.key_id
        }
    }

    #[cfg(feature = "test-utils")]
    mod mock {
        use super::*;

        impl MockTestUtil for SshConfig {
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

    impl IntegrationTestUtils for SshIntegration {
        fn mock_private_key_str() -> impl AsRef<str> {
            indoc::indoc! {"
                -----BEGIN OPENSSH PRIVATE KEY-----
                b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
                QyNTUxOQAAACCqXNhxWMjTyTSg7LGdVOslVOvESpOxG6rWcnPmOGzNdQAAAIiGLlH7hi5R
                +wAAAAtzc2gtZWQyNTUxOQAAACCqXNhxWMjTyTSg7LGdVOslVOvESpOxG6rWcnPmOGzNdQ
                AAAEBCJzkd1gqkKEOwa7hImOocahudvrdj0YuFEDdoW8pEAKpc2HFYyNPJNKDssZ1U6yVU
                68RKk7EbqtZyc+Y4bM11AAAAAAECAwQF
                -----END OPENSSH PRIVATE KEY-----
            "}
        }

        fn mock_encrypted_data_key_str() -> &'static str {
            indoc::indoc! {"
                -----BEGIN AGE ENCRYPTED FILE-----
                YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IFEzbm5LZyB1Vjdm
                eXBxbTJQSUJoR0k1czBJL1Z5ck9tUDJ1cTFXVThvL2djWkE0YzFJCklWbCtsM3g1
                TGlMZHBCaWI5LzlEQUJwWVNjcmVIWG9LbmY4YVZnN3U5THMKLT4gRi1ncmVhc2Ug
                N3hOcEZqbCAraWpAYyBHLy9TCnpBanZhOS9GbUlwRGJ3TkJwVUNsdWZhQjZqM2V4
                Y2FqdXhRbUdvK3FMZUQ0ay96bENRCi0tLSA4WU5FcUxwTEM2LzJxRC9FbkJrcHFl
                cGtIeW0rREtIdkNudWdGRndSUFJFCov7r8oL5m9qnK5qnuNzgFpsh5woQV5d+2Ff
                WVt7WUVqjWx4cP6M6Rgz/YxIzoXgC7p6kbHRdT/rlHWj8V4NTJc=
                -----END AGE ENCRYPTED FILE-----
            "}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    generate_integration_test_suite!(SshIntegration);

    #[test]
    fn derives_key_id_from_private_key() {
        assert_eq!(
            SshKeyId::mock(),
            SshIntegration::mock_private_key()
                .to_key_id()
                .expect("key id derivable from ed25519 key")
        )
    }

    #[test]
    fn key_id_round_trips_through_display() {
        assert_eq!(SshKeyId::mock_display(), SshKeyId::mock().to_string())
    }

    #[test]
    fn rejects_non_ssh_key_id() {
        assert!(SshIntegration::parse_key_id("age1se5ghfycr4n8kcwc3qwf234ymvmr2lex2a99wh8gpfx97glwt9hqch4569").is_err())
    }

    #[test]
    fn parses_multiple_private_keys_by_pem_boundaries() {
        let private_key_str = SshIntegration::mock_private_key_str();
        let two_keys = format!("{}\n\n{}", private_key_str.as_ref(), private_key_str.as_ref());

        assert_eq!(2, SshIntegration::parse_private_keys(&two_keys).unwrap().len())
    }

    #[test]
    fn rejects_unterminated_pem_block() {
        let private_key_str = SshIntegration::mock_private_key_str();
        let unterminated = private_key_str.as_ref().lines().take(3).collect::<Vec<_>>().join("\n");

        assert!(SshIntegration::parse_private_keys(&unterminated).is_err())
    }
}
