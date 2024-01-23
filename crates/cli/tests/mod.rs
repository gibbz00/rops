use rops::*;
use rops_cli::*;

use std::process::{Command, Output};

#[test]
fn disallows_both_stdin_and_file() {
    let mut cmd = Command::package_command().encrypt();
    cmd.arg("/tmp/file.txt");

    let output = cmd.run_piped("piped input");
    output.assert_failure();
    assert!(output.stderr_str().contains(&RopsCliError::MultipleInputs.to_string()));
}

#[test]
fn disallows_missing_stdin_and_file() {
    let output = Command::package_command().encrypt().run_tty();
    output.assert_failure();
    assert!(output.stderr_str().contains(&RopsCliError::MissingInput.to_string()));
}

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

test_binary::build_test_binary_once!(mock_editor, "test_bins");

#[test]
fn edits_from_stdin() {
    let encrypted_str = sops_yaml_str!("age_example");
    let encrypted_output = Command::package_command().edit_age().run_piped(encrypted_str);
    // TEMP(XXX)
    println!("{}", encrypted_output.stdout_str());
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

fn assert_encrypted<I: IntegrationTestUtils>(encrypted_output: Output, expected_plaintext: &str) {
    let decrypted_file = decrypt_output::<I>(encrypted_output);
    pretty_assertions::assert_eq!(expected_plaintext, decrypted_file.map().to_string());
}

fn decrypt_output<I: IntegrationTestUtils>(encrypted_output: Output) -> RopsFile<DecryptedFile<DefaultHasher>, YamlFileFormat> {
    encrypted_output.assert_success();
    decrypt_str::<I>(encrypted_output.stdout_str())
}

fn decrypt_str<I: IntegrationTestUtils>(encrypted_str: &str) -> RopsFile<DecryptedFile<DefaultHasher>, YamlFileFormat> {
    I::set_mock_private_key_env_var();
    encrypted_str
        .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, YamlFileFormat>>()
        .unwrap()
        .decrypt::<YamlFileFormat>()
        .unwrap()
}

fn assert_decrypted_output(decrypted_output: Output) {
    decrypted_output.assert_success();
    let decrypted_rops_file = decrypted_output
        .stdout_str()
        .parse::<RopsFile<DecryptedFile<DefaultHasher>, YamlFileFormat>>()
        .unwrap();
    pretty_assertions::assert_eq!(sops_yaml_str!("age_example_plaintext"), decrypted_rops_file.map().to_string())
}

trait EncryptCommand {
    fn encrypt(self) -> Self;

    fn partial_encryption(self) -> Self;
}
impl EncryptCommand for Command {
    fn encrypt(mut self) -> Self {
        self.arg("encrypt");
        self.args(["--age", &<AgeIntegration as Integration>::KeyId::mock_display()]);
        self.format_args()
    }

    fn partial_encryption(mut self) -> Self {
        self.arg(format!("--unencrypted-suffix={}", PartialEncryptionConfig::mock_display()));
        self
    }
}

#[rustfmt::skip]
trait DecryptCommand { fn decrypt_age(self) -> Self; }
impl DecryptCommand for Command {
    fn decrypt_age(mut self) -> Self {
        AgeIntegration::set_mock_private_key_env_var();
        self.arg("decrypt");
        self.format_args()
    }
}

const EDIT_CONTENT: &str = "hello: editor\n";
#[rustfmt::skip]
trait EditCommand { fn edit_age(self) -> Self; }
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

#[rustfmt::skip]
trait CommonArgs { fn format_args(self) -> Self; }
impl CommonArgs for Command {
    fn format_args(mut self) -> Self {
        self.args(["--format", "yaml"]);
        self
    }
}

pub(crate) use sops_references::{sops_yaml_path, sops_yaml_str};
mod sops_references {
    macro_rules! sops_yaml_str {
        ($file:literal) => {
            include_str!(sops_yaml_path!($file))
        };
    }
    pub(crate) use sops_yaml_str;

    macro_rules! sops_yaml_path {
        ($file:literal) => {
            concat!(env!("CARGO_MANIFEST_DIR"), "/../lib/tests/sops_references/", $file, ".yaml")
        };
    }
    pub(crate) use sops_yaml_path;
}

pub use command_utils::{OutputExitAssertions, OutputString, PackageCommand, RunCommand};
mod command_utils {
    use std::{
        io::Write,
        path::PathBuf,
        process::{Command, Output, Stdio},
    };

    #[rustfmt::skip]
    pub trait PackageCommand { fn package_command() -> Command; }
    impl PackageCommand for Command {
        fn package_command() -> Command {
            let mut cmd = Command::new(bin_path());
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            return cmd;

            fn bin_path() -> PathBuf {
                let mut bin_dir = std::env::current_exe().unwrap();
                bin_dir.pop();

                if bin_dir.ends_with("deps") {
                    bin_dir.pop();
                }

                let bin_path = bin_dir.join(env!("CARGO_PKG_NAME"));
                assert!(bin_path.is_file(), "function not called from within an integration test");
                bin_path
            }
        }
    }

    pub trait OutputString {
        fn stdout_str(&self) -> &str;
        fn stderr_str(&self) -> &str;
    }

    impl OutputString for Output {
        fn stdout_str(&self) -> &str {
            std::str::from_utf8(&self.stdout).unwrap()
        }

        fn stderr_str(&self) -> &str {
            std::str::from_utf8(&self.stderr).unwrap()
        }
    }

    pub trait OutputExitAssertions: OutputString {
        fn assert_success(&self);
        fn assert_failure(&self);
    }

    impl OutputExitAssertions for Output {
        fn assert_success(&self) {
            assert!(self.status.success())
        }

        fn assert_failure(&self) {
            assert!(!self.status.success())
        }
    }

    pub trait RunCommand {
        fn run_piped(self, stdin_str: &str) -> Output;
        fn run_tty(self) -> Output;
    }

    impl RunCommand for Command {
        fn run_piped(mut self, stdin_str: &str) -> Output {
            self.stdin(Stdio::piped());

            let mut child = self.spawn().unwrap();

            let mut stdin = child.stdin.take().unwrap();
            writeln!(&mut stdin, "{}", stdin_str).unwrap();
            drop(stdin);

            child.wait_with_output().unwrap()
        }

        fn run_tty(mut self) -> Output {
            self.spawn().unwrap().wait_with_output().unwrap()
        }
    }
}
