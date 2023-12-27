mod core;
pub use core::FileFormat;

mod adapters;
pub(crate) use adapters::{FileFormatKeyAdapter, FileFormatMapAdapter, FileFormatValueAdapter};

mod map;
pub use map::{FormatToInternalMapError, RopsFileFormatMap};

#[cfg(feature = "yaml")]
mod yaml;
#[cfg(feature = "yaml")]
pub use yaml::YamlFileFormat;

#[cfg(feature = "json")]
mod json;
#[cfg(feature = "json")]
pub use json::JsonFileFormat;

#[cfg(feature = "test-utils")]
mod test_utils;
#[cfg(feature = "test-utils")]
pub use test_utils::{FileFormatTestSuiteUtils, FileFormatTestUtils, MockFileFormatUtil};
