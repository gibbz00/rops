use super::*;

#[test]
fn applies_config_creation_rule() {
    let mut cmd = Command::package_command().encrypt();

    let tempfile = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tempfile.path(),
        DefaulConfigFileFormat::serialize_to_string(&Config::mock_other()).unwrap(),
    )
    .unwrap();

    cmd.args(["--config", tempfile.path().to_str().unwrap()]);
    cmd.arg(sops_yaml_path!("age_example_plaintext"));

    let output = cmd.run_tty();
    output.assert_success();

    let encrypted_rops_file = output
        .stdout_str()
        .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, YamlFileFormat>>()
        .unwrap();

    assert_eq!(2, encrypted_rops_file.metadata().intregation.age.len())
}
