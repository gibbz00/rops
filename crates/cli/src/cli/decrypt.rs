use rops::*;

use crate::*;

impl Cli {
    pub fn decrypt(decrypt_args: DecryptArgs) -> anyhow::Result<()> {
        let input_args = decrypt_args.input_args;
        let explicit_file_path = input_args.file.as_deref();
        let format = Self::get_format(explicit_file_path, input_args.format)?;
        let input_string = Self::get_input_string(explicit_file_path, decrypt_args.in_place)?;
        let decrypted_rops_file_string = decrypt_rops_file(format, &input_string)?;

        match decrypt_args.in_place.unwrap_or_default() {
            true => {
                std::fs::write(explicit_file_path.expect(IN_PLACE_PANIC), decrypted_rops_file_string)?;
            }
            false => {
                println!("{}", decrypted_rops_file_string);
            }
        }

        return Ok(());

        fn decrypt_rops_file(format: Format, encrypted_rops_file_str: &str) -> anyhow::Result<String> {
            return match format {
                Format::Yaml => decrypt_rops_file_impl::<YamlFileFormat>(encrypted_rops_file_str),
                Format::Json => decrypt_rops_file_impl::<JsonFileFormat>(encrypted_rops_file_str),
                Format::Toml => decrypt_rops_file_impl::<TomlFileFormat>(encrypted_rops_file_str),
            };

            fn decrypt_rops_file_impl<F: FileFormat>(encrypted_rops_file_str: &str) -> anyhow::Result<String> {
                encrypted_rops_file_str
                    .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, F>>()?
                    .decrypt::<F>()
                    .map(|decrypted_rops_file| decrypted_rops_file.map().to_string())
                    .map_err(Into::into)
            }
        }
    }
}
