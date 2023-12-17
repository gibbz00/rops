use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "F: FileFormat")]
pub struct RopsFile<S: RopsFileState, F: FileFormat> {
    #[serde(flatten)]
    pub map: RopsFileFormatMap<S, F>,
    #[serde(rename = "sops")]
    pub metadata: RopsFileMetadata,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<S: RopsFileState, F: FileFormat> MockTestUtil for RopsFile<S, F>
    where
        RopsFileFormatMap<S, F>: MockTestUtil,
    {
        fn mock() -> Self {
            Self {
                map: MockTestUtil::mock(),
                metadata: MockTestUtil::mock(),
            }
        }
    }
}
