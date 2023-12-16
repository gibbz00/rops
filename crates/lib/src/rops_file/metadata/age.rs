use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

use crate::*;

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RopsFileAgeMetadata {
    #[serde_as(as = "DisplayFromStr")]
    #[serde(rename = "recipient")]
    pub public_key: <AgeIntegration as Integration>::PublicKey,
    #[serde(rename = "enc")]
    pub encrypted_data_key: String,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for RopsFileAgeMetadata {
        fn mock() -> Self {
            Self {
                public_key: AgeIntegration::mock_public_key(),
                encrypted_data_key: AgeIntegration::mock_encrypted_data_key_str().to_string(),
            }
        }
    }
}
