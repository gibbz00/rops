use derive_more::Display;
use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, PartialEq, Serialize, Deserialize, Display)]
#[serde(transparent)]
pub struct LastModifiedDateTime(Timestamp);

impl LastModifiedDateTime {
    pub fn now() -> Self {
        Self(Timestamp::now())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use crate::*;

    impl MockTestUtil for LastModifiedDateTime {
        fn mock() -> Self {
            Self::mock_display().parse().map(Self).unwrap()
        }
    }

    impl MockDisplayTestUtil for LastModifiedDateTime {
        fn mock_display() -> String {
            "2023-12-27T20:37:05Z".to_string()
        }
    }
}
