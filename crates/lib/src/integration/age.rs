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
    type KeyId = AgeKeyId;
    type PrivateKey = AgePrivateKey;
    type Config = AgeConfig;

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

                    if line.starts_with(AgePrivateKey::PEM_END_PREFIX) {
                        private_keys.push(Self::parse_private_key(&pem_block)?);
                        pem_block.clear();
                    }
                }
                true => match line.starts_with(AgePrivateKey::PEM_BEGIN_PREFIX) {
                    true => {
                        pem_block.push_str(line);
                        pem_block.push('\n');
                    }
                    false => {
                        if !line.is_empty() {
                            private_keys.push(Self::parse_private_key(line)?)
                        }
                    }
                },
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
        let unarmored_buffer = {
            // IMPROVEMENT: avoid vec box allocation
            let encryptor =
                age::Encryptor::with_recipients([key_id.as_recipient()].into_iter()).expect("provided recipients should be non-empty");

            let mut unarmored_encrypted_buffer = Vec::with_capacity(DataKey::byte_size());
            let mut encryption_writer = encryptor.wrap_output(&mut unarmored_encrypted_buffer)?;
            encryption_writer.write_all(data_key.as_ref())?;
            encryption_writer.finish()?;
            unarmored_encrypted_buffer
        };

        let mut armored_buffer = Vec::with_capacity(Self::APPROX_MAX_ARMORED_DATA_KEY_LENGTH);
        let mut armored_writer = ArmoredWriter::wrap_output(&mut armored_buffer, Format::AsciiArmor)?;
        armored_writer.write_all(&unarmored_buffer)?;
        armored_writer.finish()?;

        Ok(String::from_utf8(armored_buffer)?)
    }

    fn decrypt_data_key(key_id: &Self::KeyId, encrypted_data_key: &str) -> IntegrationResult<Option<DataKey>> {
        let private_keys = Self::retrieve_private_keys()?;

        let matched_private_keys = private_keys
            .iter()
            .filter(|private_key| private_key.to_key_id().as_ref() == Some(key_id))
            .map(AgePrivateKey::as_identity)
            .collect::<Vec<_>>();

        if matched_private_keys.is_empty() {
            return Ok(None);
        }

        let mut unarmored_encrypted_buffer = Vec::with_capacity(Self::APPROX_MAX_ARMORED_DATA_KEY_LENGTH);

        ArmoredReader::new(encrypted_data_key.as_bytes()).read_to_end(&mut unarmored_encrypted_buffer)?;

        let decryptor = Decryptor::new(unarmored_encrypted_buffer.as_slice())?;

        let mut decrypted_data_key_buffer = DataKey::empty();
        let mut reader = decryptor.decrypt(matched_private_keys.into_iter())?;
        reader.read_exact(decrypted_data_key_buffer.as_mut())?;

        Ok(Some(decrypted_data_key_buffer))
    }

    fn select_metadata_units(integration_metadata: &mut IntegrationMetadata) -> &mut IntegrationMetadataUnits<Self> {
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

pub use key_id::AgeKeyId;
mod key_id {
    use std::{
        fmt::{Display, Formatter, Result as FmtResult},
        hash::{Hash, Hasher},
        str::FromStr,
    };

    use crate::*;

    /// Recipient of an age encrypted data key.
    ///
    /// `sops` stores SSH public keys alongside native age recipients in the
    /// `age` metadata field, telling them apart by their prefix. Doing the same
    /// keeps rops able to read and write those files.
    #[derive(Debug, Clone)]
    pub enum AgeKeyId {
        X25519(age::x25519::Recipient),
        #[cfg(feature = "ssh")]
        Ssh(Box<age::ssh::Recipient>),
    }

    impl AgeKeyId {
        const SSH_PREFIX: &'static str = "ssh-";

        pub(super) fn as_recipient(&self) -> &dyn age::Recipient {
            match self {
                Self::X25519(recipient) => recipient,
                #[cfg(feature = "ssh")]
                Self::Ssh(recipient) => recipient.as_ref(),
            }
        }

        #[cfg(feature = "ssh")]
        fn ssh_from_str(key_id_str: &str) -> anyhow::Result<Self> {
            key_id_str
                .parse::<age::ssh::Recipient>()
                .map(|recipient| Self::Ssh(Box::new(recipient)))
                // age::ssh::ParseRecipientKeyError does not implement Display.
                .map_err(|error| anyhow::anyhow!("invalid SSH recipient: {:?}", error))
        }

        #[cfg(not(feature = "ssh"))]
        fn ssh_from_str(_key_id_str: &str) -> anyhow::Result<Self> {
            Err(anyhow::anyhow!(
                "SSH recipients require the 'ssh' feature of the 'rops' crate to be enabled"
            ))
        }
    }

    impl FromStr for AgeKeyId {
        type Err = anyhow::Error;

        fn from_str(key_id_str: &str) -> Result<Self, Self::Err> {
            let key_id_str = key_id_str.trim();

            match key_id_str.starts_with(Self::SSH_PREFIX) {
                true => Self::ssh_from_str(key_id_str),
                false => key_id_str.parse().map(Self::X25519).map_err(|error: &str| anyhow::anyhow!(error)),
            }
        }
    }

    impl Display for AgeKeyId {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            match self {
                Self::X25519(recipient) => recipient.fmt(f),
                #[cfg(feature = "ssh")]
                Self::Ssh(recipient) => recipient.fmt(f),
            }
        }
    }

    // Manually implemented because age::ssh::Recipient derives neither
    // PartialEq nor Hash; its string representation is canonical.
    impl PartialEq for AgeKeyId {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::X25519(this), Self::X25519(other)) => this == other,
                #[cfg(feature = "ssh")]
                (Self::Ssh(this), Self::Ssh(other)) => this.to_string() == other.to_string(),
                #[cfg(feature = "ssh")]
                _ => false,
            }
        }
    }

    impl Eq for AgeKeyId {}

    impl Hash for AgeKeyId {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.to_string().hash(state)
        }
    }

    impl AppendIntegrationKey<AgeIntegration> for AgeKeyId {
        fn append_to_metadata_builder(self, integration_metadata_builder: &mut IntegrationMetadataBuilder) {
            integration_metadata_builder.age_key_ids.push(self)
        }
    }

    #[cfg(feature = "test-utils")]
    mod mock {
        use super::*;

        impl MockDisplayTestUtil for AgeKeyId {
            fn mock_display() -> String {
                "age1se5ghfycr4n8kcwc3qwf234ymvmr2lex2a99wh8gpfx97glwt9hqch4569".to_string()
            }
        }

        impl MockTestUtil for AgeKeyId {
            fn mock() -> Self {
                Self::mock_display().parse().unwrap()
            }
        }

        impl MockOtherTestUtil for AgeKeyId {
            fn mock_other() -> Self {
                "age1qazf43xll4ramx3wcn7h2yl9scycxdhrwge8862vv6zj97pafdvq0d5mn6".parse().unwrap()
            }
        }
    }
}

pub use private_key::AgePrivateKey;
mod private_key {
    use std::str::FromStr;

    use crate::*;

    /// Identity able to decrypt an age encrypted data key.
    ///
    /// Either a native age identity (`AGE-SECRET-KEY-1...`) or an unencrypted
    /// OpenSSH private key, matching the recipient kinds of [`AgeKeyId`].
    pub enum AgePrivateKey {
        X25519(age::x25519::Identity),
        #[cfg(feature = "ssh")]
        Ssh(Box<age::ssh::Identity>),
    }

    impl AgePrivateKey {
        pub(super) const PEM_BEGIN_PREFIX: &'static str = "-----BEGIN";
        pub(super) const PEM_END_PREFIX: &'static str = "-----END";

        pub(super) fn as_identity(&self) -> &dyn age::Identity {
            match self {
                Self::X25519(identity) => identity,
                #[cfg(feature = "ssh")]
                Self::Ssh(identity) => identity.as_ref(),
            }
        }

        /// Recipient this private key decrypts for, if it can be derived.
        pub(super) fn to_key_id(&self) -> Option<AgeKeyId> {
            match self {
                Self::X25519(identity) => Some(AgeKeyId::X25519(identity.to_public())),
                #[cfg(feature = "ssh")]
                Self::Ssh(identity) => age::ssh::Recipient::try_from(identity.as_ref().clone())
                    .ok()
                    .map(|recipient| AgeKeyId::Ssh(Box::new(recipient))),
            }
        }

        #[cfg(feature = "ssh")]
        fn ssh_from_str(private_key_str: &str) -> anyhow::Result<Self> {
            match age::ssh::Identity::from_buffer(private_key_str.as_bytes(), None)? {
                identity @ age::ssh::Identity::Unencrypted(_) => Ok(Self::Ssh(Box::new(identity))),
                // Rejected rather than skipped so as to not mistake a key which
                // could have been used for one which simply does not match.
                age::ssh::Identity::Encrypted(_) => Err(anyhow::anyhow!("passphrase protected SSH private keys are not supported")),
                age::ssh::Identity::Unsupported(_) => Err(anyhow::anyhow!("unsupported SSH private key type")),
            }
        }

        #[cfg(not(feature = "ssh"))]
        fn ssh_from_str(_private_key_str: &str) -> anyhow::Result<Self> {
            Err(anyhow::anyhow!(
                "SSH private keys require the 'ssh' feature of the 'rops' crate to be enabled"
            ))
        }
    }

    impl FromStr for AgePrivateKey {
        type Err = anyhow::Error;

        fn from_str(private_key_str: &str) -> Result<Self, Self::Err> {
            let private_key_str = private_key_str.trim();

            match private_key_str.starts_with(Self::PEM_BEGIN_PREFIX) {
                true => Self::ssh_from_str(private_key_str),
                false => private_key_str
                    .parse()
                    .map(Self::X25519)
                    .map_err(|error: &str| anyhow::anyhow!(error)),
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

    #[cfg(feature = "ssh")]
    pub(super) const MOCK_SSH_PRIVATE_KEY_STR: &str = indoc::indoc! {"
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACCqXNhxWMjTyTSg7LGdVOslVOvESpOxG6rWcnPmOGzNdQAAAIiGLlH7hi5R
        +wAAAAtzc2gtZWQyNTUxOQAAACCqXNhxWMjTyTSg7LGdVOslVOvESpOxG6rWcnPmOGzNdQ
        AAAEBCJzkd1gqkKEOwa7hImOocahudvrdj0YuFEDdoW8pEAKpc2HFYyNPJNKDssZ1U6yVU
        68RKk7EbqtZyc+Y4bM11AAAAAAECAwQF
        -----END OPENSSH PRIVATE KEY-----
    "};

    impl IntegrationTestUtils for AgeIntegration {
        fn mock_private_key_str() -> impl AsRef<str> {
            "AGE-SECRET-KEY-1EQUCGFZH8UZKSZ0Z5N5T234YRNDT4U9H7QNYXWRRNJYDDVXE6FWSCPGNJ7"
        }

        /// Exports the mock SSH private key alongside the native one so that
        /// tests of either recipient kind may run in parallel without
        /// overwriting each other's environment variable.
        #[cfg(feature = "ssh")]
        fn set_mock_private_key_env_var() {
            std::env::set_var(
                Self::private_key_env_var_name(),
                format!("{},{}", Self::mock_private_key_str().as_ref(), MOCK_SSH_PRIVATE_KEY_STR),
            )
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

    #[cfg(feature = "ssh")]
    mod ssh {
        use super::*;

        use mock::MOCK_SSH_PRIVATE_KEY_STR as SSH_PRIVATE_KEY_STR;

        /// Public key of [`SSH_PRIVATE_KEY_STR`] in the `authorized_keys` format.
        const SSH_KEY_ID_STR: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpc2HFYyNPJNKDssZ1U6yVU68RKk7EbqtZyc+Y4bM11";

        #[test]
        fn key_id_round_trips_through_display() {
            assert_eq!(SSH_KEY_ID_STR, AgeIntegration::parse_key_id(SSH_KEY_ID_STR).unwrap().to_string())
        }

        #[test]
        fn derives_key_id_from_private_key() {
            assert_eq!(
                AgeIntegration::parse_key_id(SSH_KEY_ID_STR).unwrap(),
                AgeIntegration::parse_private_key(SSH_PRIVATE_KEY_STR).unwrap().to_key_id().unwrap()
            )
        }

        #[test]
        fn parses_private_keys_of_mixed_kinds() {
            let mixed = format!("{}\n{}", AgeIntegration::mock_private_key_str().as_ref(), SSH_PRIVATE_KEY_STR);
            let private_keys = AgeIntegration::parse_private_keys(&mixed).unwrap();

            assert_eq!(
                vec![Some(AgeKeyId::mock()), Some(AgeIntegration::parse_key_id(SSH_KEY_ID_STR).unwrap())],
                private_keys.iter().map(AgePrivateKey::to_key_id).collect::<Vec<_>>()
            )
        }

        #[test]
        fn encrypts_and_decrypts_data_key() {
            AgeIntegration::set_mock_private_key_env_var();

            let key_id = AgeIntegration::parse_key_id(SSH_KEY_ID_STR).unwrap();
            let expected_data_key = DataKey::mock();
            let encrypted_data_key = AgeIntegration::encrypt_data_key(&key_id, &expected_data_key).unwrap();

            assert_eq!(
                expected_data_key,
                AgeIntegration::decrypt_data_key(&key_id, &encrypted_data_key).unwrap().unwrap()
            )
        }
    }
}
