use std::{
    io::{IsTerminal, Read},
    path::Path,
};

use anyhow::bail;
use clap::ValueEnum;

use crate::*;

impl Cli {
    pub fn get_plaintext_string(file_path: Option<&Path>, in_place: Option<bool>) -> anyhow::Result<String> {
        let mut stdin_guard = std::io::stdin().lock();

        let plaintext_string = match in_place.unwrap_or_default() {
            true => read_from_path(file_path.expect(IN_PLACE_PANIC), stdin_guard)?,
            false => match &file_path {
                Some(plaintext_path) => read_from_path(plaintext_path, stdin_guard)?,
                None => {
                    if stdin_guard.is_terminal() {
                        bail!(RopsCliError::MissingInput)
                    }
                    let mut stdin_string = String::new();
                    stdin_guard.read_to_string(&mut stdin_string)?;
                    stdin_string
                }
            },
        };

        return Ok(plaintext_string);

        fn read_from_path(path: &Path, stdin_guard: std::io::StdinLock<'_>) -> anyhow::Result<String> {
            if !stdin_guard.is_terminal() {
                bail!(RopsCliError::MultipleInputs)
            }
            drop(stdin_guard);

            std::fs::read_to_string(path).map_err(Into::into)
        }
    }

    pub fn get_format(explicit_file_path: Option<&Path>, explicit_format: Option<Format>) -> Result<Format, RopsCliError> {
        match explicit_format {
            Some(format) => Ok(format),
            None => match explicit_file_path {
                Some(file_path) => file_path
                    .extension()
                    .and_then(|file_extension| {
                        <Format as ValueEnum>::from_str(file_extension.to_str().expect("invalid unicode"), true).ok()
                    })
                    .ok_or_else(|| UndeterminedFormatError::NoFileExtention(file_path.to_path_buf()).into()),
                None => Err(UndeterminedFormatError::FoundNeither.into()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_format_by_extesion() {
        assert_eq!(Format::Yaml, Cli::get_format(Some(Path::new("test.yaml")), None).unwrap())
    }

    #[test]
    fn infers_format_by_extesion_alias() {
        assert_eq!(Format::Yaml, Cli::get_format(Some(Path::new("test.yml")), None).unwrap())
    }

    #[test]
    fn both_missing_is_undetermined_format() {
        assert_eq!(
            RopsCliError::UndeterminedFormat(UndeterminedFormatError::FoundNeither),
            Cli::get_format(None, None).unwrap_err()
        )
    }

    #[test]
    fn errors_on_missing_file_extension() {
        assert!(matches!(
            Cli::get_format(Some(Path::new("test")), None).unwrap_err(),
            RopsCliError::UndeterminedFormat(UndeterminedFormatError::NoFileExtention(_))
        ))
    }
}
