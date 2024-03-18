use crate::*;

#[derive(Clone, Copy)]
pub struct MacOnlyEncryptedConfig<'a> {
    pub mac_only_encrypted: bool,
    pub resolved_partial_encryption: ResolvedPartialEncryption<'a>,
}

impl MacOnlyEncryptedConfig<'_> {
    pub fn new<'a>(
        mac_only_encrypted: Option<bool>,
        partial_encryption: Option<&'a PartialEncryptionConfig>,
    ) -> MacOnlyEncryptedConfig<'a> {
        MacOnlyEncryptedConfig::<'a> {
            mac_only_encrypted: mac_only_encrypted.unwrap_or_default(),
            resolved_partial_encryption: partial_encryption.into(),
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for MacOnlyEncryptedConfig<'_> {
        fn mock() -> Self {
            Self {
                mac_only_encrypted: false,
                resolved_partial_encryption: ResolvedPartialEncryption::mock(),
            }
        }
    }
}
