use super::*;

use super::encryption::utils::*;

#[test]
fn edits_from_stdin() {
    let encrypted_str = sops_yaml_str!("age_example");
    let encrypted_output = Command::package_command().edit_age().run_piped(encrypted_str);
    assert_encrypted::<AgeIntegration>(encrypted_output, EDIT_CONTENT);
}

#[test]
fn edits_from_file() {
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), sops_yaml_str!("age_example")).unwrap();

    let mut cmd = Command::package_command().edit_age();
    cmd.arg(temp_file.path());
    cmd.run_tty();

    let encrypted_content = std::fs::read_to_string(temp_file.path()).unwrap();
    pretty_assertions::assert_eq!(EDIT_CONTENT, decrypt_str::<AgeIntegration>(&encrypted_content).map().to_string())
}

use utils::{EditCommand, EDIT_CONTENT};
mod utils {
    use super::*;

    pub const EDIT_CONTENT: &str = "hello: editor\n";
    pub trait EditCommand {
        fn edit_age(self) -> Self;
    }
    impl EditCommand for Command {
        fn edit_age(mut self) -> Self {
            std::env::set_var(
                "EDITOR",
                format!("{} '{}'", path_to_mock_editor().to_str().expect("valid unicode"), EDIT_CONTENT),
            );
            AgeIntegration::set_mock_private_key_env_var();

            self.arg("edit");
            self.format_args()
        }
    }
}
