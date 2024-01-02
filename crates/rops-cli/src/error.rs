#[derive(Debug, thiserror::Error)]
pub enum RopsCliError {
    #[error("multiple inputs; recieved content from stdin when a file path was provided")]
    MultipleInputs,
    #[error("missing input; neither a file path nor stdin were provided")]
    MissingInput,
}
