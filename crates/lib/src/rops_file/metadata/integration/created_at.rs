use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IntegrationCreatedAt(Timestamp);

impl IntegrationCreatedAt {
    pub fn now() -> Self {
        Self(Timestamp::now())
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for IntegrationCreatedAt {
        fn mock() -> Self {
            Self::mock_display().parse().map(Self).unwrap()
        }
    }

    impl MockDisplayTestUtil for IntegrationCreatedAt {
        fn mock_display() -> String {
            "2023-12-28T21:18:02Z".to_string()
        }
    }
}
