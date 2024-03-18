use std::path::PathBuf;

use thiserror::Error;

// TEMP: Test misspeling to fail CI.

#[derive(Debug, PartialEq, Error)]
pub enum RopsCliError {
    #[error("multiple inputs; received content from stdin when a file path was provided")]
    MultipleInputs,
    #[error("missing input; neither a file path nor stdin were provided")]
    MissingInput,
    #[error("unable to determine input format; {0}")]
    UndeterminedFormat(#[from] UndeterminedFormatError),
}

#[derive(Debug, PartialEq, Error)]
pub enum UndeterminedFormatError {
    #[error("found neither format nor file arguments")]
    FoundNeither,
    #[error("unable to determine file extension for {0} when no format argument was found")]
    NoFileExtension(PathBuf),
}

pub const IN_PLACE_PANIC: &str = "inplace argument not declared with a #[requires = \"file\"] field attribute.";
