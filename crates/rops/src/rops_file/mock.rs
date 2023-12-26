use std::{fmt::Display, str::FromStr};

use crate::*;

impl<S: RopsFileState, F: FileFormat> MockTestUtil for RopsFile<S, F>
where
    RopsFileFormatMap<S::MapState, F>: MockTestUtil,
    RopsFileMetadata<S::MetadataState>: MockTestUtil,
    <<S::MetadataState as RopsMetadataState>::Mac as FromStr>::Err: Display,
{
    fn mock() -> Self {
        Self {
            map: MockTestUtil::mock(),
            metadata: MockTestUtil::mock(),
        }
    }
}
