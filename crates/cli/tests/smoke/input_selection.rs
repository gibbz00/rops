use super::*;

use super::encryption::utils::*;

#[test]
fn disallows_both_stdin_and_file() {
    disallows_both_impl(false)
}

#[test]
fn disallows_both_stdin_and_file_for_inplace_too() {
    disallows_both_impl(true)
}

#[test]
fn disallows_missing_stdin_and_file() {
    let output = Command::package_command().encrypt().run_tty();
    output.assert_failure();
    assert!(output.stderr_str().contains(&RopsCliError::MissingInput.to_string()));
}

fn disallows_both_impl(in_place: bool) {
    let cmd = Command::package_command();
    let mut cmd = match in_place {
        true => cmd.encrypt_in_place(),
        false => cmd.encrypt(),
    };

    cmd.arg("/tmp/file.txt");

    let output = cmd.run_piped("piped input");
    output.assert_failure();
    assert!(output.stderr_str().contains(&RopsCliError::MultipleInputs.to_string()));
}
