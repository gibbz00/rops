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

            let bin_path = bin_dir.join(env!("CARGO_BIN_EXE_rops"));
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

pub trait CommonArgs {
    fn format_args(self) -> Self;
}
impl CommonArgs for Command {
    fn format_args(mut self) -> Self {
        self.args(["--format", "yaml"]);
        self
    }
}
