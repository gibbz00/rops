use super::*;

#[test]
fn decrypts_from_stdin() {
    let encrypted_str = sops_yaml_str!("age_example");
    let decrypted_output = Command::package_command().decrypt_age().run_piped(encrypted_str);
    assert_decrypted_output(decrypted_output);
}

#[test]
fn decrypts_from_file() {
    let mut cmd = Command::package_command().decrypt_age();
    cmd.arg(sops_yaml_path!("age_example"));
    assert_decrypted_output(cmd.run_tty())
}

#[test]
fn decrypts_in_place() {
    let mut cmd = Command::package_command().decrypt_age_in_place();
    let encrypted_text = sops_yaml_str!("age_example");

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), encrypted_text).unwrap();
    cmd.arg(temp_file.path());

    cmd.run_tty().assert_success();

    pretty_assertions::assert_eq!(
        sops_yaml_str!("age_example_plaintext"),
        std::fs::read_to_string(temp_file.path()).unwrap()
    )
}

use utils::{assert_decrypted_output, DecryptCommand};
mod utils {
    use super::*;

    pub fn assert_decrypted_output(decrypted_output: Output) {
        decrypted_output.assert_success();
        pretty_assertions::assert_eq!(
            format!("{}\n", sops_yaml_str!("age_example_plaintext")),
            decrypted_output.stdout_str()
        )
    }
    pub trait DecryptCommand {
        fn decrypt_age(self) -> Self;
        fn decrypt_age_in_place(self) -> Self;
    }
    impl DecryptCommand for Command {
        fn decrypt_age(mut self) -> Self {
            AgeIntegration::set_mock_private_key_env_var();
            self.arg("decrypt");
            self.format_args()
        }

        fn decrypt_age_in_place(self) -> Self {
            let mut cmd = self.decrypt_age();
            cmd.arg("--in-place");
            cmd
        }
    }
}
