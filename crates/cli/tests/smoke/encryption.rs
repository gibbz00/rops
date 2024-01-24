use super::*;

#[test]
fn encrypts_with_age() {
    let plaintext = sops_yaml_str!("age_example_plaintext");
    let output = Command::package_command().encrypt().run_piped(plaintext);
    assert_encrypted::<AgeIntegration>(output, plaintext);
}

#[test]
fn encrypts_with_aws_kms() {
    let plaintext = sops_yaml_str!("aws_kms_example_plaintext");
    let output = Command::package_command().encrypt().run_piped(plaintext);
    assert_encrypted::<AwsKmsIntegration>(output, plaintext);
}

#[test]
fn encrypts_from_file() {
    let mut cmd = Command::package_command().encrypt();
    cmd.arg(sops_yaml_path!("age_example_plaintext"));
    assert_encrypted::<AgeIntegration>(cmd.run_tty(), sops_yaml_str!("age_example_plaintext"));
}

#[test]
fn encrypts_in_place() {
    let mut cmd = Command::package_command().encrypt_in_place();
    let plaintext = sops_yaml_str!("age_example_plaintext");

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), plaintext).unwrap();
    cmd.arg(temp_file.path());

    cmd.run_tty().assert_success();

    let encrypted_content = std::fs::read_to_string(temp_file.path()).unwrap();
    pretty_assertions::assert_eq!(plaintext, decrypt_str::<AgeIntegration>(&encrypted_content).map().to_string())
}

#[test]
fn encrypts_with_partial_encryption() {
    let plaintext = sops_yaml_str!("age_unencrypted_suffix_plaintext");
    let output = Command::package_command().encrypt().partial_encryption().run_piped(plaintext);
    let decrypted_file = decrypt_output::<AgeIntegration>(output);
    assert_eq!(Some(PartialEncryptionConfig::mock()), decrypted_file.metadata().partial_encryption)
}

#[test]
fn encrypts_with_mac_encrypted_only() {
    let mut cmd = Command::package_command().encrypt().partial_encryption();
    cmd.arg("--mac-only-encrypted");

    let plaintext = sops_yaml_str!("age_mac_only_encrypted_plaintext");
    let decrypted_file = decrypt_output::<AgeIntegration>(cmd.run_piped(plaintext));
    assert_eq!(Some(true), decrypted_file.metadata().mac_only_encrypted)
}

use utils::{assert_encrypted, decrypt_output, decrypt_str, EncryptCommand};
pub mod utils {
    use super::*;

    pub fn decrypt_output<I: IntegrationTestUtils>(encrypted_output: Output) -> RopsFile<DecryptedFile<DefaultHasher>, YamlFileFormat> {
        encrypted_output.assert_success();
        decrypt_str::<I>(encrypted_output.stdout_str())
    }

    pub fn decrypt_str<I: IntegrationTestUtils>(encrypted_str: &str) -> RopsFile<DecryptedFile<DefaultHasher>, YamlFileFormat> {
        I::set_mock_private_key_env_var();
        encrypted_str
            .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, YamlFileFormat>>()
            .unwrap()
            .decrypt::<YamlFileFormat>()
            .unwrap()
    }

    pub fn assert_encrypted<I: IntegrationTestUtils>(encrypted_output: Output, expected_plaintext: &str) {
        let decrypted_file = decrypt_output::<I>(encrypted_output);
        pretty_assertions::assert_eq!(expected_plaintext, decrypted_file.map().to_string());
    }

    pub trait EncryptCommand {
        fn encrypt(self) -> Self;
        fn encrypt_in_place(self) -> Self;

        fn partial_encryption(self) -> Self;
    }

    impl EncryptCommand for Command {
        fn encrypt(mut self) -> Self {
            self.arg("encrypt");
            self.args(["--age", &<AgeIntegration as Integration>::KeyId::mock_display()]);
            self.format_args()
        }

        fn encrypt_in_place(self) -> Self {
            let mut cmd = self.encrypt();
            cmd.arg("--in-place");
            cmd
        }

        fn partial_encryption(mut self) -> Self {
            self.arg(format!("--unencrypted-suffix={}", PartialEncryptionConfig::mock_display()));
            self
        }
    }
}
