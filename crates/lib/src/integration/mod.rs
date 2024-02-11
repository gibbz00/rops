mod core;
pub use core::Integration;
pub(crate) use core::IntegrationConfig;

mod error;
pub(crate) use error::{IntegrationError, IntegrationResult};

#[cfg(feature = "age")]
mod age;
#[cfg(all(test, feature = "age"))]
pub(crate) use age::AgeConfig;
#[cfg(feature = "age")]
pub use age::AgeIntegration;

#[cfg(feature = "aws-kms")]
mod aws_kms;
#[cfg(feature = "aws-kms")]
pub use aws_kms::AwsKmsIntegration;
#[cfg(feature = "aws-kms")]
pub(crate) use aws_kms::*;

#[cfg(feature = "test-utils")]
mod test_utils;
#[cfg(feature = "test-utils")]
pub use test_utils::IntegrationTestUtils;

#[cfg(test)]
mod test_suite;
#[cfg(test)]
pub(crate) use test_suite::generate_integration_test_suite;
