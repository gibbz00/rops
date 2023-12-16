use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RopsFileMap<S: RopsFileState, F: FileFormat> {
    #[serde(flatten)]
    inner: F::Map,
    #[serde(skip)]
    state_marker: PhantomData<S>,
}

impl<S: RopsFileState, F: FileFormat> RopsFileMap<S, F> {
    pub fn into_inner_map(self) -> F::Map {
        self.inner
    }

    #[cfg(feature = "test-utils")]
    pub fn from_inner_map(inner: F::Map) -> Self {
        Self {
            inner,
            state_marker: PhantomData,
        }
    }
}
