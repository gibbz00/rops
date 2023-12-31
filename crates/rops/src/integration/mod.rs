mod core;
pub use core::{Integration, IntegrationConfig};

mod key_id;
pub use key_id::IntegrationKeyId;

mod error;
pub use error::{IntegrationError, IntegrationResult};

#[cfg(feature = "age")]
mod age;
#[cfg(feature = "age")]
pub use age::{AgeConfig, AgeIntegration};

#[cfg(feature = "aws-kms")]
mod aws_kms;
#[cfg(feature = "aws-kms")]
pub use aws_kms::*;

#[cfg(feature = "test-utils")]
mod test_utils;
#[cfg(feature = "test-utils")]
pub use test_utils::{IntegrationTestUtils, StubIntegration};

#[cfg(test)]
pub(crate) use test_suite::generate_integration_test_suite;
#[cfg(test)]
mod test_suite;
