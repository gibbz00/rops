use std::{fmt::Display, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self {
        Self(Utc::now())
    }
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.format("%Y-%m-%dT%H:%M:%SZ"))
    }
}

#[cfg(feature = "test-utils")]
impl FromStr for Timestamp {
    type Err = chrono::ParseError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        str.parse().map(Self)
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use crate::*;

    impl MockTestUtil for Timestamp {
        fn mock() -> Self {
            Self::mock_display().parse().map(Self).unwrap()
        }
    }

    impl MockDisplayTestUtil for Timestamp {
        fn mock_display() -> String {
            "2023-12-27T20:37:05Z".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn displays_date_time_correctly() {
        DisplayTestUtils::assert_display::<Timestamp>();
    }

    #[test]
    fn skips_nanosecond_display() {
        assert_eq!(Timestamp::mock_display().len(), Timestamp::now().to_string().len())
    }
}
