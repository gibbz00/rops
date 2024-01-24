use rops::*;

use crate::*;

impl Cli {
    pub fn keys(key_command: KeysSubcommand) -> anyhow::Result<()> {
        match key_command {
            KeysSubcommand::Add(key_args) => Self::add_keys(key_args),
            KeysSubcommand::Remove(key_args) => Self::remove_keys(key_args),
        }
    }

    fn add_keys(key_args: KeyInputArgs) -> anyhow::Result<()> {
        return match Self::get_format(Some(&key_args.file), key_args.format)? {
            Format::Yaml => add_key_impl::<YamlFileFormat>(key_args),
            Format::Json => add_key_impl::<JsonFileFormat>(key_args),
        };

        fn add_key_impl<F: FileFormat>(key_args: KeyInputArgs) -> anyhow::Result<()> {
            let mut rops_file =
                Cli::get_input_string(Some(&key_args.file), None)?.parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, F>>()?;

            let keys = key_args.intregration_keys;
            rops_file.add_keys::<AgeIntegration>(keys.age_keys)?;
            rops_file.add_keys::<AwsKmsIntegration>(keys.aws_kms_keys)?;

            std::fs::write(key_args.file, rops_file.to_string())?;

            Ok(())
        }
    }

    fn remove_keys(key_args: KeyInputArgs) -> anyhow::Result<()> {
        return match Self::get_format(Some(&key_args.file), key_args.format)? {
            Format::Yaml => remove_key_impl::<YamlFileFormat>(key_args),
            Format::Json => remove_key_impl::<JsonFileFormat>(key_args),
        };

        fn remove_key_impl<F: FileFormat>(key_args: KeyInputArgs) -> anyhow::Result<()> {
            let mut decrypted_rops_file = Cli::get_input_string(Some(&key_args.file), None)?
                .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, F>>()?
                .decrypt::<F>()?;

            let keys = key_args.intregration_keys;

            // IMPROVEMENT: return error if any key not found?
            for age_key in keys.age_keys {
                decrypted_rops_file.remove_integration_key::<AgeIntegration>(&age_key)?;
            }

            for aws_key in keys.aws_kms_keys {
                decrypted_rops_file.remove_integration_key::<AwsKmsIntegration>(&aws_key)?;
            }

            std::fs::write(key_args.file, decrypted_rops_file.encrypt::<DefaultCipher, F>()?.to_string())?;

            Ok(())
        }
    }
}
