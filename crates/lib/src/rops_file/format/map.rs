use std::{fmt::Display, marker::PhantomData};

use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Serialize, Deserialize)]
#[impl_tools::autoimpl(Debug, PartialEq)]
#[serde(transparent)]
pub struct RopsFileFormatMap<S: RopsMapState, F: FileFormat> {
    #[serde(flatten)]
    inner: F::Map,
    #[serde(skip)]
    state_marker: PhantomData<S>,
}

// IMPROVEMENT: Might be worth splitting distinguishing decrypted and
// encrypted map to tree errors by separating then into two enums.
#[derive(Debug, thiserror::Error)]
pub enum FormatToInternalMapError {
    #[error("only string keys are supported, found: {0}")]
    NonStringKey(String),
    #[error("integer out of range, allowed values must fit inside an i64, found: {0}")]
    IntegerOutOfRange(u64),
    #[error("unable to parse encrypted value components: {0}")]
    EncryptedRopsValue(#[from] EncryptedRopsValueFromStrError),
    #[error("encountered plaintext value when it should have been encrypted")]
    PlaintextWhenEncrypted(String),
}

impl<S: RopsMapState, F: FileFormat> RopsFileFormatMap<S, F> {
    pub fn into_inner_map(self) -> F::Map {
        self.inner
    }

    pub fn from_inner_map(inner: F::Map) -> Self {
        Self {
            inner,
            state_marker: PhantomData,
        }
    }
}

impl<C: Cipher, F: FileFormat> RopsFileFormatMap<EncryptedMap<C>, F> {
    pub fn to_internal(
        self,
        partial_encryption: Option<&PartialEncryptionConfig>,
    ) -> Result<RopsMap<EncryptedMap<C>>, FormatToInternalMapError> {
        self.into_inner_map().encrypted_to_internal(
            partial_encryption.into(),
            <F::Map as FileFormatMapAdapter>::Value::encrypted_to_internal,
        )
    }
}

impl<F: FileFormat> RopsFileFormatMap<DecryptedMap, F> {
    pub fn to_internal(self) -> Result<RopsMap<DecryptedMap>, FormatToInternalMapError> {
        self.into_inner_map().decrypted_to_internal()
    }
}

impl<S: RopsMapState, F: FileFormat> Display for RopsFileFormatMap<S, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", F::serialize_to_string(self).expect("file format map not serializable"))
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<S: RopsMapState, F: FileFormat> MockTestUtil for RopsFileFormatMap<S, F>
    where
        Self: MockFileFormatUtil<F>,
    {
        fn mock() -> Self {
            F::deserialize_from_str(&Self::mock_format_display()).expect("mock map string not serializable")
        }
    }

    impl<S: RopsMapState, F: FileFormat> MockOtherTestUtil for RopsFileFormatMap<S, F>
    where
        RopsMap<S>: MockOtherTestUtil,
        RopsMap<S>: ToExternalMap<S>,
    {
        fn mock_other() -> Self {
            RopsMap::mock_other().to_external()
        }
    }
}
