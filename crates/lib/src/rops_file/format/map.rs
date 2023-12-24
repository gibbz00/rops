use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, Serialize, Deserialize)]
#[impl_tools::autoimpl(PartialEq)]
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
    // TEMP: Deprecate once partial encryption feature arrives.
    #[error("invalid value type for an encrypted file")]
    InvalidValueTypeForEncrypted(String),
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
