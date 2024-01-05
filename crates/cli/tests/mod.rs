use rops::*;
use rops_cli::*;

use std::{
    path::PathBuf,
    process::{Command, Output},
};

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
fn encrypts_from_stdin() {
    let output = Command::package_command().encrypt().run_piped(plaintext_age_example());
    assert_encrypted_age_example(output);
}

#[test]
fn encrypts_from_file() {
    let mut cmd = Command::package_command().encrypt();
    cmd.arg(plaintext_age_example_path().into_os_string());
    assert_encrypted_age_example(cmd.run_tty());
}

fn assert_encrypted_age_example(encrypted_output: Output) {
    encrypted_output.assert_success();
    let decrypted_file = decrypt_output(encrypted_output);
    pretty_assertions::assert_eq!(plaintext_age_example(), decrypted_file.map().to_string());
}

#[test]
fn encrypts_with_partial_encryption() {
    let mut cmd = Command::package_command().encrypt();
    cmd.arg(format!("--unencrypted-suffix={}", PartialEncryptionConfig::mock_display()));

    let output = cmd.run_piped(plaintext_age_unencrypted_suffix());
    output.assert_success();

    let decrypted_file = decrypt_output(output);
    assert_eq!(Some(PartialEncryptionConfig::mock()), decrypted_file.metadata().partial_encryption)
}

fn decrypt_output(encrypted_output: Output) -> RopsFile<DecryptedFile<DefaultHasher>, YamlFileFormat> {
    AgeIntegration::set_mock_private_key_env_var();
    encrypted_output
        .stdout_str()
        .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, YamlFileFormat>>()
        .unwrap()
        .decrypt::<YamlFileFormat>()
        .unwrap()
}

#[rustfmt::skip]
    trait EncryptCommand { fn encrypt(self) -> Self; }
impl EncryptCommand for Command {
    fn encrypt(mut self) -> Self {
        self.arg("encrypt");
        self.args(["--age", &<AgeIntegration as Integration>::KeyId::mock_display()]);
        self.common_args()
    }
}

#[test]
fn decrypts_from_stdin() {
    let decrypted_output = Command::package_command().decrypt_age().run_piped(encrypted_age_example());
    assert_decrypted_output(decrypted_output);
}

#[test]
fn decrypts_from_file() {
    let mut cmd = Command::package_command().decrypt_age();
    cmd.arg(encrypted_age_example_path().into_os_string());
    assert_decrypted_output(cmd.run_tty())
}

fn assert_decrypted_output(decrypted_output: Output) {
    decrypted_output.assert_success();
    let decrypted_rops_file = decrypted_output
        .stdout_str()
        .parse::<RopsFile<DecryptedFile<DefaultHasher>, YamlFileFormat>>()
        .unwrap();
    pretty_assertions::assert_eq!(plaintext_age_example(), decrypted_rops_file.map().to_string())
}

#[rustfmt::skip]
trait DecryptCommand { fn decrypt_age(self) -> Self; }
impl DecryptCommand for Command {
    fn decrypt_age(mut self) -> Self {
        AgeIntegration::set_mock_private_key_env_var();

        self.arg("decrypt");
        self.common_args()
    }
}

#[rustfmt::skip]
trait CommonArgs { fn common_args(self) -> Self; }
impl CommonArgs for Command {
    fn common_args(mut self) -> Self {
        self.args(["--format", "yaml"]);
        self
    }
}

// IMPROVEMENT: unify with rops/tests/parity_checks.rs

fn plaintext_age_example() -> &'static str {
    include_str!("../../lib/tests/sops_references/age_example_plaintext.yaml")
}

fn plaintext_age_example_path() -> PathBuf {
    let file_path = sops_references_dir().join("age_example_plaintext.yaml");
    assert!(file_path.is_file());
    file_path
}

fn encrypted_age_example() -> &'static str {
    include_str!("../../lib/tests/sops_references/age_example.yaml")
}

fn plaintext_age_unencrypted_suffix() -> &'static str {
    include_str!("../../lib/tests/sops_references/age_unencrypted_suffix_plaintext.yaml")
}

fn encrypted_age_example_path() -> PathBuf {
    let file_path = sops_references_dir().join("age_example.yaml");
    assert!(file_path.is_file());
    file_path
}

fn sops_references_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // crates/
        .unwrap()
        .join("lib/tests/sops_references");

    assert!(dir.is_dir());

    dir
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
