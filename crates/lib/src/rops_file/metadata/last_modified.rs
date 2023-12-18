use std::fmt::Display;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct LastModifiedDateTime(DateTime<Utc>);

impl LastModifiedDateTime {
    pub fn now() -> Self {
        Self(Utc::now())
    }
}

impl Display for LastModifiedDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.format("%Y-%m-%dT%H:%M:%SZ"))
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use crate::*;

    impl MockDisplayTestUtil for LastModifiedDateTime {
        fn mock_display() -> String {
            "2023-12-16T22:32:54Z".to_string()
        }
    }

    impl MockTestUtil for LastModifiedDateTime {
        fn mock() -> Self {
            "2023-12-16T22:32:54Z".parse().map(Self).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn displays_date_time_correctly() {
        DisplayTestUtils::assert_display::<LastModifiedDateTime>();
    }

    #[test]
    fn skips_nanosecond_display() {
        assert_eq!(
            LastModifiedDateTime::mock_display().len(),
            LastModifiedDateTime::now().to_string().len()
        )
    }
}
