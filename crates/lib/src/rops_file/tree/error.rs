#[derive(Debug, thiserror::Error)]
pub enum RopsTreeBuildError {
    #[error("only string keys are supported, found: {0}")]
    NonStringKey(String),
    #[error("integer out of range, allowed values must fit inside an i64, found: {0}")]
    IntegerOutOfRange(u64),
}
