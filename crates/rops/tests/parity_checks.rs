use rops::*;

#[test]
fn example_without_comment() -> anyhow::Result<()> {
    let sops_file = include_str!("./sops_references/age_example.yaml");
    // Normalize to serde_yaml format:
    let sops_file = serde_yaml::from_str::<serde_yaml::Value>(sops_file).and_then(|value| serde_yaml::to_string(&value))?;

    let sops_file_plaintext = include_str!("./sops_references/age_example_plaintext.yaml");
    // Normalize to serde_yaml format:
    let sops_file_plaintext =
        serde_yaml::from_str::<serde_yaml::Value>(sops_file_plaintext).and_then(|value| serde_yaml::to_string(&value))?;

    IntegrationsTestUtils::set_private_keys();

    let (decrypted_rops_file, saved_parameters) = sops_file
        .parse::<RopsFile<EncryptedFile<AES256GCM, SHA512>, YamlFileFormat>>()?
        .decrypt_and_save_parameters()?;

    pretty_assertions::assert_eq!(sops_file_plaintext, decrypted_rops_file.map.to_string());

    pretty_assertions::assert_eq!(
        sops_file,
        decrypted_rops_file
            .encrypt_with_saved_parameters::<AES256GCM, YamlFileFormat>(saved_parameters)?
            .to_string()
    );

    Ok(())
}
