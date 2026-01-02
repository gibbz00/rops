use std::{io::IsTerminal, path::Path, process::Command};

use anyhow::{bail, Context};
use rops::file::{format::*, map::state::*, state::*, RopsFile};

use crate::*;

impl Cli {
    pub fn edit(input_args: InputArgs) -> anyhow::Result<()> {
        let explicit_file_path = input_args.file.as_deref();

        return match Self::get_format(explicit_file_path, input_args.format)? {
            Format::Yaml => edit_encrypted_file::<YamlFileFormat>(explicit_file_path),
            Format::Json => edit_encrypted_file::<JsonFileFormat>(explicit_file_path),
            Format::Toml => edit_encrypted_file::<TomlFileFormat>(explicit_file_path),
        };

        // Nested to avoid it being misused for regular files which might use aliases.
        // (E.g 'yml' over 'yaml'.)
        #[rustfmt::skip]
        mod temp_file_format {
            use super::*;
            pub trait TempFileFormat: FileFormat { const TEMP_EXTENSION: &'static str; }
            impl TempFileFormat for YamlFileFormat { const TEMP_EXTENSION: &'static str = "yaml"; }
            impl TempFileFormat for JsonFileFormat { const TEMP_EXTENSION: &'static str = "json"; }
            impl TempFileFormat for TomlFileFormat { const TEMP_EXTENSION: &'static str = "toml"; }
        }

        fn edit_encrypted_file<F: temp_file_format::TempFileFormat>(explicit_file_path: Option<&Path>) -> anyhow::Result<()> {
            let (decrypted_rops_file, saved_parameters) = Cli::get_input_string(explicit_file_path, None)?
                .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, F>>()?
                .decrypt_and_save_parameters::<F>()?;

            let temp_file = tempfile::Builder::new()
                .suffix(&format!(".{}", F::TEMP_EXTENSION))
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
                false => println!("{encrypted_rops_file_string}"),
            }

            return Ok(());

            fn select_editor() -> anyhow::Result<(String, Vec<String>)> {
                use which::which;
                match std::env::var_os("EDITOR") {
                    Some(editor_env) => {
                        let editor_value = editor_env.to_str().context("$EDITOR value is invalid UTF-8")?;
                        let mut parts_iter = shlex::split(editor_value)
                            .context(format!("unable to parse $EDITOR value {editor_value}"))?
                            .into_iter();
                        let command = parts_iter.next().expect("$EDITOR value should not have been empty");
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
                            eprintln!("Unable to parse map: {err}");
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
}

#[cfg(test)]
mod tests {
    // TODO: ensure correctness on other platforms
    #[cfg(unix)]
    mod unix_perissions {
        #[test]
        fn temp_file_has_600_permissions() {
            use std::os::unix::fs::PermissionsExt;
            let tempfile = tempfile::tempfile().unwrap();
            let mode = tempfile.metadata().unwrap().permissions().mode();
            const MODE: u32 = 0o600;
            assert_eq!(MODE, MODE & mode)
        }
    }
}
