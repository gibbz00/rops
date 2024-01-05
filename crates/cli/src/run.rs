use std::{
    io::{IsTerminal, Read},
    path::Path,
};

use anyhow::bail;
use clap::{Parser, ValueEnum};
use rops::{AgeIntegration, AwsKmsIntegration, EncryptedFile, FileFormat, JsonFileFormat, RopsFile, RopsFileBuilder, YamlFileFormat};

use crate::*;

pub fn run() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    match args.cmd {
        CliCommand::Encrypt(encrypt_args) => {
            let explicit_file_path = encrypt_args.input_args.file.as_deref();
            let plaintext_string = get_plaintext_string(explicit_file_path)?;

            match get_format(explicit_file_path, encrypt_args.input_args.format)? {
                Format::Yaml => {
                    encrypt_rops_file::<YamlFileFormat>(&plaintext_string, encrypt_args)?;
                }
                Format::Json => {
                    encrypt_rops_file::<JsonFileFormat>(&plaintext_string, encrypt_args)?;
                }
            }

            fn encrypt_rops_file<F: FileFormat>(plaintext_str: &str, encrypt_args: EncryptArgs) -> anyhow::Result<()> {
                let mut rops_file_builder = RopsFileBuilder::<F>::new(plaintext_str)?
                    .add_integration_keys::<AgeIntegration>(encrypt_args.age_keys)
                    .add_integration_keys::<AwsKmsIntegration>(encrypt_args.aws_kms_keys);

                if let Some(partial_encryption_args) = encrypt_args.partial_encryption_args {
                    rops_file_builder = rops_file_builder.with_partial_encryption(partial_encryption_args.into())
                }

                let encrypted_rops_file = rops_file_builder.encrypt::<DefaultCipher, DefaultHasher>()?;
                println!("{}", encrypted_rops_file);

                Ok(())
            }
        }
        CliCommand::Decrypt(input_args) => {
            let explicit_file_path = input_args.file.as_deref();
            let plaintext_string = get_plaintext_string(explicit_file_path)?;
            let format = get_format(explicit_file_path, input_args.format)?;

            match format {
                Format::Yaml => decrypt_rops_file::<YamlFileFormat>(&plaintext_string)?,
                Format::Json => decrypt_rops_file::<JsonFileFormat>(&plaintext_string)?,
            }

            fn decrypt_rops_file<F: FileFormat>(plaintext_str: &str) -> anyhow::Result<()> {
                let decrypted_rops_file = plaintext_str
                    .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, F>>()?
                    .decrypt::<F>()?;

                println!("{}", decrypted_rops_file);

                Ok(())
            }
        }
    }

    Ok(())
}

fn get_plaintext_string(file_path: Option<&Path>) -> anyhow::Result<String> {
    let mut stdin_guard = std::io::stdin().lock();

    let plaintext_string = match &file_path {
        Some(plaintext_path) => {
            if !stdin_guard.is_terminal() {
                bail!(RopsCliError::MultipleInputs)
            }
            drop(stdin_guard);
            std::fs::read_to_string(plaintext_path)?
        }
        None => {
            if stdin_guard.is_terminal() {
                bail!(RopsCliError::MissingInput)
            }
            let mut stdin_string = String::new();
            stdin_guard.read_to_string(&mut stdin_string)?;
            stdin_string
        }
    };

    Ok(plaintext_string)
}

fn get_format(explicit_file_path: Option<&Path>, explicit_format: Option<Format>) -> Result<Format, RopsCliError> {
    match explicit_format {
        Some(format) => Ok(format),
        None => match explicit_file_path {
            Some(file_path) => file_path
                .extension()
                .and_then(|file_extension| <Format as ValueEnum>::from_str(file_extension.to_str().expect("invalid unicode"), true).ok())
                .ok_or_else(|| UndeterminedFormatError::NoFileExtention(file_path.to_path_buf()).into()),
            None => Err(UndeterminedFormatError::FoundNeither.into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_format_by_extesion() {
        assert_eq!(Format::Yaml, get_format(Some(Path::new("test.yaml")), None).unwrap())
    }

    #[test]
    fn infers_format_by_extesion_alias() {
        assert_eq!(Format::Yaml, get_format(Some(Path::new("test.yml")), None).unwrap())
    }

    #[test]
    fn both_missing_is_undetermined_format() {
        assert_eq!(
            RopsCliError::UndeterminedFormat(UndeterminedFormatError::FoundNeither),
            get_format(None, None).unwrap_err()
        )
    }

    #[test]
    fn errors_on_missing_file_extension() {
        assert!(matches!(
            get_format(Some(Path::new("test")), None).unwrap_err(),
            RopsCliError::UndeterminedFormat(UndeterminedFormatError::NoFileExtention(_))
        ))
    }
}
