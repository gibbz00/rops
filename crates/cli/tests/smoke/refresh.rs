use pretty_assertions::assert_eq;
use tempfile::NamedTempFile;

use super::*;

#[test]
fn refreshes_metadata_config_from_file() {
    let temp_config_file = NamedTempFile::new().unwrap();
    store_config_other(temp_config_file.path());

    let temp_rops_file = NamedTempFile::new().unwrap();
    store_rops_file(temp_rops_file.path());

    let initial_rops_file = initial_rops_file();

    assert!(initial_rops_file.metadata().partial_encryption.is_some());
    assert!(initial_rops_file.metadata().mac_only_encrypted.is_none());
    assert_eq!(1, initial_rops_file.metadata().intregation.age.len());
    assert!(initial_rops_file
        .metadata()
        .intregation
        .age
        .contains_key(&<<AgeIntegration as Integration>::KeyId>::mock()));

    let mut cmd = Command::package_command().refresh(temp_config_file.path());
    cmd.arg(temp_rops_file.path());

    let refreshed_rops_file = refreshed_rops_file(&cmd.run_tty());

    assert!(refreshed_rops_file.metadata().partial_encryption.is_none());
    assert!(refreshed_rops_file.metadata().mac_only_encrypted.is_some());
    assert_eq!(1, refreshed_rops_file.metadata().intregation.age.len());
    assert!(refreshed_rops_file
        .metadata()
        .intregation
        .age
        .contains_key(&<<AgeIntegration as Integration>::KeyId>::mock_other()));
}

#[test]
fn refreshes_metadata_config_from_stdin() {
    let temp_config_file = NamedTempFile::new().unwrap();
    store_config_other(temp_config_file.path());

    let initial_rops_file = initial_rops_file();
    let initial_last_modified = &initial_rops_file.metadata().last_modified;

    let output = Command::package_command()
        .refresh(temp_config_file.path())
        .run_piped(TEST_ENCRYPTED_ROPS_FILE);

    let refreshed_rops_file = refreshed_rops_file(&output);

    assert_ne!(initial_last_modified, &refreshed_rops_file.metadata().last_modified)
}

#[test]
fn skips_refresh_if_possible() {
    let temp_config_file = NamedTempFile::new().unwrap();
    store_config_other(temp_config_file.path());

    let output = Command::package_command()
        .refresh(temp_config_file.path())
        .run_piped(TEST_ENCRYPTED_ROPS_FILE);

    let first_rops_file = refreshed_rops_file(&output);

    let second_output = Command::package_command()
        .refresh(temp_config_file.path())
        .run_piped(output.stdout_str());

    let second_rops_file = refreshed_rops_file(&second_output);

    assert_eq!(first_rops_file, second_rops_file)
}

use utils::{initial_rops_file, refreshed_rops_file, store_config_other, store_rops_file, RefreshCommand, TEST_ENCRYPTED_ROPS_FILE};
mod utils {
    use std::path::Path;

    use super::*;

    pub const TEST_ENCRYPTED_ROPS_FILE: &str = sops_yaml_str!("age_unencrypted_suffix");

    type TestRopsFile = RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, YamlFileFormat>;

    pub trait RefreshCommand {
        fn refresh(self, config_path: &Path) -> Self;
    }

    impl RefreshCommand for Command {
        fn refresh(mut self, config_path: &Path) -> Self {
            AgeIntegration::set_mock_private_key_env_var();
            self.arg("refresh");
            self.args(["--config", config_path.to_str().unwrap()]);
            self.format_args()
        }
    }

    pub fn store_config_other(config_path: &Path) {
        std::fs::write(
            config_path,
            DefaulConfigFileFormat::serialize_to_string(&Config::mock_other()).unwrap(),
        )
        .unwrap()
    }

    pub fn store_rops_file(rops_file_path: &Path) {
        std::fs::write(rops_file_path, TEST_ENCRYPTED_ROPS_FILE).unwrap()
    }

    pub fn initial_rops_file() -> TestRopsFile {
        TEST_ENCRYPTED_ROPS_FILE.parse::<TestRopsFile>().unwrap()
    }

    pub fn refreshed_rops_file(cmd_output: &Output) -> TestRopsFile {
        cmd_output.assert_success();
        cmd_output.stdout_str().parse().unwrap()
    }
}
