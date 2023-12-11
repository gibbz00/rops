mod core;
pub use core::Integration;

mod error;
pub use error::{IntegrationError, IntegrationResult};

#[cfg(feature = "age")]
mod age;
#[cfg(feature = "age")]
pub use age::AgeIntegration;

#[cfg(feature = "test-utils")]
mod test_utils;
#[cfg(feature = "test-utils")]
pub use test_utils::IntegrationTestUtils;
