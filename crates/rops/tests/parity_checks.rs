#[cfg(all(feature = "age", feature = "yaml", feature = "aes-gcm", feature = "sha2"))]
mod age_yaml_aes_gcm_sha2 {
    use crate::*;

    age_parity_check!(example);
    age_parity_check!(encrypted_suffix);
    age_parity_check!(encrypted_regex);
    age_parity_check!(unencrypted_suffix);
    age_parity_check!(unencrypted_regex);
    age_parity_check!(mac_only_encrypted);

    #[macro_export]
    macro_rules! age_parity_check {
        ($name:tt) => {
            parity_check!("age", AgeIntegration, $name);
        };
    }
}

#[cfg(all(feature = "aws-kms", feature = "yaml", feature = "aes-gcm", feature = "sha2"))]
mod aws_kms_yaml_aes_gcm_sha2 {
    use crate::*;

    aws_kms_parity_check!(example);

    #[macro_export]
    macro_rules! aws_kms_parity_check {
        ($name:tt) => {
            parity_check!("aws_kms", AwsKmsIntegration, $name);
        };
    }
}

#[cfg(feature = "yaml")]
mod yaml_utils {
    pub fn normalize_yaml(input_yaml: &str) -> Result<String, serde_yaml::Error> {
        serde_yaml::from_str::<serde_yaml::Value>(input_yaml).and_then(|value| serde_yaml::to_string(&value))
    }
}

#[cfg(all(feature = "yaml", feature = "aes-gcm", feature = "sha2"))]
mod yaml_aes_gcm_sha2_parity_check {
    #[macro_export]
    macro_rules! parity_check {
        ($integration_name:literal, $integration:tt, $name:tt) => {
            #[test]
            fn $name() -> anyhow::Result<()> {
                use rops::*;

                let sops_file = $crate::yaml_utils::normalize_yaml(include_str!(concat!(
                    "sops_references/",
                    $integration_name,
                    "_",
                    stringify!($name),
                    ".yaml"
                )))?;

                let sops_file_plaintext = $crate::yaml_utils::normalize_yaml(include_str!(concat!(
                    "sops_references/",
                    $integration_name,
                    "_",
                    stringify!($name),
                    "_plaintext.yaml"
                )))?;

                $integration::set_mock_private_key_env_var();

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
}
