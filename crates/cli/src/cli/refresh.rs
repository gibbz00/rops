use rops::*;

use crate::*;

impl Cli {
    pub fn refresh(refresh_args: RefreshArgs) -> anyhow::Result<()> {
        let explicit_file_path = refresh_args.input_args.file.clone();
        let in_place = refresh_args.in_place;

        let file_format = Self::get_format(explicit_file_path.as_deref(), refresh_args.input_args.format)?;
        let encrypted_rops_file_string = Self::get_input_string(explicit_file_path.as_deref(), in_place)?;
        let encrypted_rops_file_string = refresh_rops_file(file_format, encrypted_rops_file_string, refresh_args)?;

        // IMPROVEMENT: dry up with other in place calls
        match in_place.unwrap_or_default() {
            true => {
                std::fs::write(explicit_file_path.expect(IN_PLACE_PANIC), encrypted_rops_file_string)?;
            }
            false => {
                println!("{}", encrypted_rops_file_string);
            }
        }

        return Ok(());

        fn refresh_rops_file(file_format: Format, encrypted_rops_file_string: String, refresh_args: RefreshArgs) -> anyhow::Result<String> {
            return match file_format {
                Format::Yaml => refresh_rops_file_impl::<YamlFileFormat>(encrypted_rops_file_string, refresh_args),
                Format::Json => refresh_rops_file_impl::<JsonFileFormat>(encrypted_rops_file_string, refresh_args),
                Format::Toml => refresh_rops_file_impl::<TomlFileFormat>(encrypted_rops_file_string, refresh_args),
            };

            fn refresh_rops_file_impl<F: FileFormat>(
                mut encrypted_rops_file_string: String,
                refresh_args: RefreshArgs,
            ) -> anyhow::Result<String> {
                let config = Config::retrieve(refresh_args.config_path())?;
                let encrypted_rops_file = encrypted_rops_file_string.parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, F>>()?;

                // stdin regarded as empty path
                let path_to_match = refresh_args.input_args.file.unwrap_or_default();
                let path_to_match = path_to_match.to_string_lossy();

                for creation_rule in config.creation_rules {
                    if creation_rule.path_regex.is_match(&path_to_match) {
                        if !creation_rule.implies_metadata(encrypted_rops_file.metadata()) {
                            let decrypted_rops_file = encrypted_rops_file.decrypt::<F>()?;

                            // IMPROVEMENT: Dry up code with Cli::encrypt()
                            let mut rops_file_builder = creation_rule
                                .integration_keys
                                .add_to_builder(RopsFileBuilder::<F>::from_map(decrypted_rops_file.into_inner_map()));

                            if let Some(partial_encryption_args) = creation_rule.partial_encryption {
                                rops_file_builder = rops_file_builder.with_partial_encryption(partial_encryption_args)
                            }

                            if creation_rule.mac_only_encrypted.unwrap_or_default() {
                                rops_file_builder = rops_file_builder.mac_only_encrypted()
                            }

                            encrypted_rops_file_string = rops_file_builder.encrypt::<DefaultCipher, DefaultHasher>()?.to_string();
                        }

                        break;
                    }
                }

                Ok(encrypted_rops_file_string)
            }
        }
    }
}
