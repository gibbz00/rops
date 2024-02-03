mod core;
pub use core::IntegrationMetadata;

mod unit;
pub(crate) use unit::IntegrationMetadataUnit;

mod units;
pub use units::IntegrationMetadataUnits;

mod created_at;
pub(crate) use created_at::IntegrationCreatedAt;
