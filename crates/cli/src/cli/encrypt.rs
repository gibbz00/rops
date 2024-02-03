use rops::file::{builder::RopsFileBuilder, format::*};

use crate::*;

impl Cli {
    pub fn encrypt(encrypt_args: EncryptArgs) -> anyhow::Result<()> {
        let explicit_file_path = encrypt_args.input_args.file.clone();
        let in_place = encrypt_args.in_place;

        let file_format = Self::get_format(explicit_file_path.as_deref(), encrypt_args.input_args.format)?;
        let plaintext_string = Self::get_input_string(explicit_file_path.as_deref(), in_place)?;
        let encrypted_rops_file_string = encrypt_rops_file(file_format, &plaintext_string, encrypt_args)?;

        return Cli::write_or_print(in_place, explicit_file_path.as_deref(), &encrypted_rops_file_string).map_err(Into::into);

        fn encrypt_rops_file(file_format: Format, plaintext_string: &str, encrypt_args: EncryptArgs) -> anyhow::Result<String> {
            return match file_format {
                Format::Yaml => encrypt_rops_file_impl::<YamlFileFormat>(plaintext_string, encrypt_args),
                Format::Json => encrypt_rops_file_impl::<JsonFileFormat>(plaintext_string, encrypt_args),
                Format::Toml => encrypt_rops_file_impl::<TomlFileFormat>(plaintext_string, encrypt_args),
            };

            fn encrypt_rops_file_impl<F: FileFormat>(plaintext_str: &str, encrypt_args: EncryptArgs) -> anyhow::Result<String> {
                let mut rops_file_builder = encrypt_args
                    .integration_keys
                    .add_to_builder(RopsFileBuilder::<F>::new(plaintext_str)?);

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
}
