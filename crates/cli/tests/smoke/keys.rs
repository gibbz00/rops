use std::path::Path;

use tempfile::NamedTempFile;

use super::*;

#[test]
fn adds_keys() {
    let encrypted_temp_file = encrypted_tempfile();
    add_age_key_command(encrypted_temp_file.path());
    let updated_rops_file = updated_rops_file(encrypted_temp_file.path());

    assert_eq!(2, updated_rops_file.metadata().intregation.age.len())
}

#[test]
fn removes_keys() {
    let encrypted_temp_file = encrypted_tempfile();
    add_age_key_command(encrypted_temp_file.path());
    assert_eq!(2, updated_rops_file(encrypted_temp_file.path()).metadata().intregation.age.len());

    remove_age_key_command(encrypted_temp_file.path());
    assert_eq!(1, updated_rops_file(encrypted_temp_file.path()).metadata().intregation.age.len());
}

fn add_age_key_command(file_path: &Path) {
    let mut cmd = base();
    cmd.arg("add");
    finish(cmd, file_path)
}

fn remove_age_key_command(file_path: &Path) {
    let mut cmd = base();
    cmd.arg("remove");
    finish(cmd, file_path)
}

fn base() -> Command {
    AgeIntegration::set_mock_private_key_env_var();
    let mut cmd = Command::package_command();
    cmd.arg("keys");
    cmd
}

fn finish(mut cmd: Command, file_path: &Path) {
    cmd.args(["--age", &<AgeIntegration as Integration>::KeyId::mock_other().to_string()]);
    let mut cmd = cmd.format_args();
    cmd.arg(file_path);
    cmd.run_tty().assert_success();
}

fn encrypted_tempfile() -> NamedTempFile {
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), sops_yaml_str!("age_example")).unwrap();
    temp_file
}

fn updated_rops_file(updated_rops_file_path: &Path) -> RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, YamlFileFormat> {
    std::fs::read_to_string(updated_rops_file_path)
        .unwrap()
        .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, YamlFileFormat>>()
        .unwrap()
}
