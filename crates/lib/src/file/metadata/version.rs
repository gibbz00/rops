use serde::{Deserialize, Serialize};

/// Version entry of the file metadata.
///
/// SOPS records the version of the tool which wrote the file, newly encrypted
/// files therefore get the rops version. An existing value, or the lack
/// thereof, is otherwise preserved as is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MetadataVersion(String);

impl MetadataVersion {
    pub const CURRENT: &'static str = env!("CARGO_PKG_VERSION");
}

impl Default for MetadataVersion {
    fn default() -> Self {
        Self(Self::CURRENT.to_string())
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;
    use crate::*;

    impl MockTestUtil for MetadataVersion {
        fn mock() -> Self {
            Self::default()
        }
    }

    impl MockDisplayTestUtil for MetadataVersion {
        fn mock_display() -> String {
            MetadataVersion::CURRENT.to_string()
        }
    }
}
