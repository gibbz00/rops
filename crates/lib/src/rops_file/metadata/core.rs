use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RopsFileMetadata {
    #[cfg(feature = "age")]
    pub age: Vec<RopsFileAgeMetadata>,
    #[serde(rename = "lastmodified")]
    pub last_modified: LastModifiedDateTime,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for RopsFileMetadata {
        fn mock() -> Self {
            Self {
                #[cfg(feature = "age")]
                age: vec![RopsFileAgeMetadata::mock()],
                last_modified: MockTestUtil::mock(),
            }
        }
    }
}
