#[cfg(all(feature = "age", feature = "yaml", feature = "aes-gcm", feature = "sha2"))]
mod age_yaml_aes_gcm_sha2 {
    use rops::*;

    use crate::*;

    parity_check!(age_example);
    parity_check!(age_encrypted_suffix);
    parity_check!(age_encrypted_regex);
    parity_check!(age_unencrypted_suffix);
    parity_check!(age_unencrypted_regex);
    parity_check!(age_mac_only_encrypted);

    #[macro_export]
    macro_rules! parity_check {
        ($name:tt) => {
            #[test]
            fn $name() -> anyhow::Result<()> {
                let sops_file = normalize_yaml(include_str!(concat!("./sops_references/", stringify!($name), ".yaml")))?;
                let sops_file_plaintext = normalize_yaml(include_str!(concat!(
                    "./sops_references/",
                    stringify!($name),
                    "_plaintext.yaml"
                )))?;

                AgeIntegration::set_mock_private_key_env_var();

                let (decrypted_rops_file, saved_parameters) = sops_file
                    .parse::<RopsFile<EncryptedFile<AES256GCM, SHA512>, YamlFileFormat>>()
                    .unwrap()
                    .decrypt_and_save_parameters::<YamlFileFormat>()
                    .unwrap();

                pretty_assertions::assert_eq!(sops_file_plaintext, decrypted_rops_file.map.to_string());

                pretty_assertions::assert_eq!(
                    sops_file,
                    decrypted_rops_file
                        .encrypt_with_saved_parameters::<AES256GCM, YamlFileFormat>(saved_parameters)?
                        .to_string()
                );

                Ok(())
            }
        };
    }

    fn normalize_yaml(input_yaml: &str) -> Result<String, serde_yaml::Error> {
        serde_yaml::from_str::<serde_yaml::Value>(input_yaml).and_then(|value| serde_yaml::to_string(&value))
    }
}
