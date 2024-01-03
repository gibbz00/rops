use rops::*;
use rops_cli::*;

mod encrypt {
    use std::{
        io::Write,
        path::PathBuf,
        process::{Command, Output, Stdio},
    };

    use super::*;

    #[test]
    fn disallows_both_stdin_and_file() {
        let mut cmd = Command::package_command().encrypt();
        cmd.arg("/tmp/file.txt");

        let output = cmd.output().unwrap();
        output.assert_failure();
        assert!(output.stderr_str().contains(&RopsCliError::MultipleInputs.to_string()));
    }

    #[test]
    fn disallows_missing_stdin_and_file() {
        let mut cmd = Command::package_command().encrypt();

        let output = cmd.spawn().unwrap().wait_with_output().unwrap();
        output.assert_failure();
        assert!(output.stderr_str().contains(&RopsCliError::MissingInput.to_string()));
    }

    #[test]
    fn encrypts_from_stdin() {
        let mut cmd = Command::package_command().encrypt();
        cmd.stdin(Stdio::piped());

        let mut child = cmd.spawn().unwrap();

        let mut stdin = child.stdin.take().unwrap();
        writeln!(&mut stdin, "{}", plaintext_age_example()).unwrap();
        drop(stdin);

        assert_encrypted_output(child.wait_with_output().unwrap());
    }

    #[test]
    fn encrypts_from_file() {
        let mut cmd = Command::package_command().encrypt();
        cmd.arg(age_example_plaintext_path().into_os_string());
        assert_encrypted_output(cmd.spawn().unwrap().wait_with_output().unwrap());
    }

    fn assert_encrypted_output(encrypted_output: Output) {
        encrypted_output.assert_success();

        AgeIntegration::set_mock_private_key_env_var();
        let decrypted_file = encrypted_output
            .stdout_str()
            .parse::<RopsFile<EncryptedFile<DefaultCipher, DefaultHasher>, YamlFileFormat>>()
            .unwrap()
            .decrypt::<YamlFileFormat>()
            .unwrap();

        pretty_assertions::assert_eq!(plaintext_age_example(), decrypted_file.map().to_string());
    }

    #[rustfmt::skip]
    trait EncryptCommand { fn encrypt(self) -> Self; }
    impl EncryptCommand for Command {
        fn encrypt(mut self) -> Self {
            self.arg("encrypt");
            self.args(["--age", &<AgeIntegration as Integration>::KeyId::mock_display()]);
            self.args(["--format", "yaml"]);
            self
        }
    }

    // IMPROVEMENT: unify with rops/tests/parity_checks.rs
    fn plaintext_age_example() -> &'static str {
        include_str!("../../lib/tests/sops_references/age_example_plaintext.yaml")
    }

    fn age_example_plaintext_path() -> PathBuf {
        let file_path = sops_references_dir().join("age_example_plaintext.yaml");
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
}

mod decrypt {}

pub use command_utils::{OutputExitAssertions, OutputString, PackageCommand};
mod command_utils {
    use std::{
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
}
