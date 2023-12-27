use std::{fmt::Display, str::FromStr};

use crate::*;

#[derive(Clone, Copy)]
pub struct MacOnlyEncryptedConfig<'a> {
    pub mac_only_encrypted: bool,
    pub resolved_partial_encryption: ResolvedPartialEncrpytion<'a>,
}

impl MacOnlyEncryptedConfig<'_> {
    pub fn new<'a, S: RopsMetadataState>(metadata: &'a RopsFileMetadata<S>) -> MacOnlyEncryptedConfig<'a>
    where
        <S::Mac as FromStr>::Err: Display,
    {
        MacOnlyEncryptedConfig::<'a> {
            mac_only_encrypted: metadata.mac_only_encrypted.unwrap_or_default(),
            resolved_partial_encryption: metadata.partial_encryption.as_ref().into(),
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
                resolved_partial_encryption: None.into(),
            }
        }
    }
}
