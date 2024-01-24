use std::{
    io::{IsTerminal, Read},
    path::Path,
    process::Command,
};

use anyhow::{bail, Context};
use clap::{Parser, ValueEnum};
use rops::{
    AgeIntegration, AwsKmsIntegration, DecryptedMap, EncryptedFile, FileFormat, JsonFileFormat, RopsFile, RopsFileBuilder,
    RopsFileFormatMap, YamlFileFormat,
};

use crate::*;

pub fn run() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    match args.cmd {
        CliSubcommand::Encrypt(encrypt_args) => Cli::encrypt(encrypt_args),
        CliSubcommand::Decrypt(decrypt_args) => Cli::decrypt(decrypt_args),
        CliSubcommand::Edit(input_args) => Cli::edit(input_args),
        CliSubcommand::Keys(key_args) => todo!(),
    }
}

struct Cli;
impl Cli {
    fn encrypt(encrypt_args: EncryptArgs) -> anyhow::Result<()> {
        let explicit_file_path = encrypt_args.input_args.file.clone();
        let in_place = encrypt_args.in_place;

        let file_format = Self::get_format(explicit_file_path.as_deref(), encrypt_args.input_args.format)?;
        let plaintext_string = Self::get_plaintext_string(explicit_file_path.as_deref(), in_place)?;
        let encrypted_rops_file_string = encrypt_rops_file(file_format, &plaintext_string, encrypt_args)?;

        match in_place.unwrap_or_default() {
            true => {
                std::fs::write(explicit_file_path.expect(IN_PLACE_PANIC), encrypted_rops_file_string)?;
            }
            false => {
                println!("{}", encrypted_rops_file_string);
            }
        }

        return Ok(());

        fn encrypt_rops_file(file_format: Format, plaintext_string: &str, encrypt_args: EncryptArgs) -> anyhow::Result<String> {
            return match file_format {
                Format::Yaml => encrypt_rops_file_impl::<YamlFileFormat>(plaintext_string, encrypt_args),
                Format::Json => encrypt_rops_file_impl::<JsonFileFormat>(plaintext_string, encrypt_args),
            };

            fn encrypt_rops_file_impl<F: FileFormat>(plaintext_str: &str, encrypt_args: EncryptArgs) -> anyhow::Result<String> {
                let mut rops_file_builder = RopsFileBuilder::<F>::new(plaintext_str)?
                    .add_integration_keys::<AgeIntegration>(encrypt_args.intregration_keys.age_keys)
                    .add_integration_keys::<AwsKmsIntegration>(encrypt_args.intregration_keys.aws_kms_keys);

                if let Some(partial_encryption_args) = encrypt_args.partial_encryption_args {
                    rops_file_builder = rops_file_builder.with_partial_encryption(partial_encryption_args.into())
                }

                if encrypt_args.mac_only_encrypted.unwrap_or_default() {
                    rops_file_builder = rops_file_builder.mac_only_encrypted()
                }

                rops_file_builder
                    .encrypt::<DefaultCipher, DefaultHasher>()
                    .map(|rops_file| rops_file.to_string())
                    .map_err(Into::into)
            }
        }
    }

    fn decrypt(decrypt_args: DecryptArgs) -> anyhow::Result<()> {
        let input_args = decrypt_args.input_args;
        let explicit_file_path = input_args.file.as_deref();
        let format = Self::get_format(explicit_file_path, input_args.format)?;
        let plaintext_string = Self::get_plaintext_string(explicit_file_path, decrypt_args.in_place)?;
        let decrypted_rops_file_string = decrypt_rops_file(format, &plaintext_string)?;

        match decrypt_args.in_place.unwrap_or_default() {
            true => {
                std::fs::write(explicit_file_path.expect(IN_PLACE_PANIC), decrypted_rops_file_string)?;
            }
            false => {
                println!("{}", decrypted_rops_file_string);
            }
        }

        return Ok(());

        fn decrypt_rops_file(format: Format, plaintext_str: &str) -> anyhow::Result<String> {
            return match format {
                Format::Yaml => decrypt_rops_file_impl::<YamlFileFormat>(plaintext_str),
                Format::Json => decrypt_rops_file_impl::<JsonFileFormat>(plaintext_str),
            };

            fn decrypt_rops_file_impl<F: FileFormat>(plaintext_str: &str) -> anyhow::Result<String> {
                plaintext_str
                    .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, F>>()?
                    .decrypt::<F>()
                    .map(|decrypted_rops_file| decrypted_rops_file.map().to_string())
                    .map_err(Into::into)
            }
        }
    }

    fn edit(input_args: InputArgs) -> anyhow::Result<()> {
        let explicit_file_path = input_args.file.as_deref();

        return match Self::get_format(explicit_file_path, input_args.format)? {
            Format::Yaml => edit_encrypted_file::<YamlFileFormat>(explicit_file_path),
            Format::Json => edit_encrypted_file::<JsonFileFormat>(explicit_file_path),
        };

        // Nested to avoid it being misused for regular files which might use aliases.
        // (E.g 'yml' over 'yaml'.)
        #[rustfmt::skip]
        mod temp_file_format {
            use super::*;
            pub trait TempFileFormat: FileFormat { const TEMP_EXTENTION: &'static str; }
            impl TempFileFormat for YamlFileFormat { const TEMP_EXTENTION: &'static str = "yaml"; }
            impl TempFileFormat for JsonFileFormat { const TEMP_EXTENTION: &'static str = "json"; }
        }

        fn edit_encrypted_file<F: temp_file_format::TempFileFormat>(explicit_file_path: Option<&Path>) -> anyhow::Result<()> {
            let (decrypted_rops_file, saved_parameters) = Cli::get_plaintext_string(explicit_file_path, None)?
                .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, F>>()?
                .decrypt_and_save_parameters::<F>()?;

            let temp_file = tempfile::Builder::new()
                .suffix(&format!(".{}", F::TEMP_EXTENTION))
                // Create locally to avoid file being picked up by temporary resource cleaners.
                .tempfile_in("./")?;

            std::fs::write(temp_file.path(), decrypted_rops_file.map().to_string())?;

            let optional_decrypted_map = edit_temp_file::<F>(temp_file.path())?;
            drop(temp_file);

            let Some(decrypted_map) = optional_decrypted_map else {
                return Ok(());
            };

            let encrypted_rops_file_string = decrypted_rops_file
                .set_map(decrypted_map)?
                .encrypt_with_saved_parameters::<_, F>(saved_parameters)?
                .to_string();

            match std::io::stdin().lock().is_terminal() {
                true => std::fs::write(
                    explicit_file_path.expect(
                        "`get_plaintext_string()` should have checked the existence of a file argument in the absence of piped stdin",
                    ),
                    encrypted_rops_file_string,
                )?,
                false => println!("{}", encrypted_rops_file_string),
            }

            return Ok(());

            fn select_editor() -> anyhow::Result<(String, Vec<String>)> {
                use which::which;
                match std::env::var_os("EDITOR") {
                    Some(editor_env) => {
                        let editor_value = editor_env.to_str().context("$EDITOR value is invalid UTF-8")?;
                        let mut parts_iter = shlex::split(editor_value)
                            .context(format!("unable to parse $EDITOR value {}", editor_value))?
                            .into_iter();
                        let command = parts_iter.next().expect("$EDTIOR value should not have been empty");
                        Ok((command, parts_iter.collect()))
                    }
                    None => match which("vim").ok().or_else(|| which("nano").ok()).or_else(|| which("vi").ok()) {
                        Some(fallback) => Ok((fallback.to_str().expect("fallback path is invalid unicode").to_string(), Vec::new())),
                        None => bail!("unable to locate vim, nano or vi as fallback editors to a missing $EDITOR"),
                    },
                }
            }

            /// Returns Ok(None) if operation was cancelled.
            fn edit_temp_file<F: FileFormat>(temp_file_path: &Path) -> anyhow::Result<Option<RopsFileFormatMap<DecryptedMap, F>>> {
                let (editor_command, args) = select_editor()?;
                let mut command = Command::new(editor_command);
                command.args(args);
                command.arg(temp_file_path);

                // Capture SIGINT in order to clean up tempdir.
                ctrlc::try_set_handler(|| ()).expect("another ctrl-c handler has already been set");

                loop {
                    let output = command
                        .spawn()
                        .context(format!("failed to launch editor; '{}'", command.get_program().to_string_lossy()))?
                        .wait_with_output()?;

                    if !output.status.success() {
                        let error = std::str::from_utf8(&output.stderr).context("unable to read editor stderr")?;
                        bail!("editor closed with error: {},", error)
                    }

                    let temp_file_string = std::fs::read_to_string(temp_file_path)?;

                    match temp_file_string.parse() {
                        Ok(decrypted_map) => break Ok(Some(decrypted_map)),
                        Err(err) => {
                            eprintln!("Unable to parse map: {}", err);
                            eprintln!("Send SIGINT (usually Ctrl+C) to quit or any key to retry.");

                            if let Err(error) = console::Term::stdout().read_key() {
                                return match error.kind() == std::io::ErrorKind::Interrupted {
                                    true => Ok(None),
                                    false => Err(error.into()),
                                };
                            }

                            continue;
                        }
                    }
                }
            }
        }
    }

    fn get_plaintext_string(file_path: Option<&Path>, in_place: Option<bool>) -> anyhow::Result<String> {
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

    fn get_format(explicit_file_path: Option<&Path>, explicit_format: Option<Format>) -> Result<Format, RopsCliError> {
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

    // TODO: ensure correctness on other platforms
    #[cfg(unix)]
    mod unix_perissions {
        #[test]
        fn temp_file_has_600_permessions() {
            use std::os::unix::fs::PermissionsExt;
            let tempfile = tempfile::tempfile().unwrap();
            let mode = tempfile.metadata().unwrap().permissions().mode();
            const MODE: u32 = 0o600;
            assert_eq!(MODE, MODE & mode)
        }
    }
}
