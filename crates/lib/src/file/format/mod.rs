mod core;
pub use core::FileFormat;

#[cfg(feature = "yaml")]
mod yaml;
#[cfg(feature = "yaml")]
pub use yaml::YamlFileFormat;

#[cfg(feature = "json")]
mod json;
#[cfg(feature = "json")]
pub use json::JsonFileFormat;

#[cfg(feature = "toml")]
mod toml;
#[cfg(feature = "toml")]
pub use toml::TomlFileFormat;

mod adapters;
pub(crate) use adapters::{FileFormatKeyAdapter, FileFormatMapAdapter, FileFormatValueAdapter};

mod map;
pub(crate) use map::FormatToInternalMapError;
pub use map::RopsFileFormatMap;

#[cfg(feature = "test-utils")]
mod test_utils;
#[cfg(feature = "test-utils")]
pub use test_utils::{FileFormatTestSuiteUtils, FileFormatTestUtils, MockFileFormatUtil};

#[cfg(test)]
mod test_suite;
#[cfg(test)]
pub(crate) use test_suite::{generate_file_format_test_suite, generate_integration_metadata_test_suite};
