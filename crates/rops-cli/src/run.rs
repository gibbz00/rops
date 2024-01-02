use std::io::{IsTerminal, Read};

use anyhow::bail;
use clap::Parser;
use rops::{AgeIntegration, EncryptedFile, FileFormat, JsonFileFormat, RopsFile, RopsFileBuilder, YamlFileFormat};

use crate::*;

pub fn run() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    match args {
        CliArgs::Encrypt(encrypt_args) => {
            let mut stdin_guard = std::io::stdin().lock();

            let plaintext_string = match &encrypt_args.file {
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

            match encrypt_args.format {
                Format::Yaml => {
                    let encrypted_rops_file = encrypt_rops_file::<YamlFileFormat>(&plaintext_string, encrypt_args)?;
                    println!("{}", encrypted_rops_file);
                }
                Format::Json => {
                    let encrypted_rops_file = encrypt_rops_file::<JsonFileFormat>(&plaintext_string, encrypt_args)?;
                    println!("{}", encrypted_rops_file);
                }
            };

            fn encrypt_rops_file<F: FileFormat>(
                plaintext_str: &str,
                encrypt_args: EncryptArgs,
            ) -> anyhow::Result<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, F>> {
                RopsFileBuilder::new(plaintext_str)?
                    .add_integration_keys::<AgeIntegration>(encrypt_args.age_keys)
                    .encrypt()
                    .map_err(Into::into)
            }
        }
        CliArgs::Decrypt(_) => todo!(),
    }

    Ok(())
}
