// TODO: remove star import
use rops::{integration::*, test_utils::*, *};
use rops_cli::*;

use std::process::{Command, Output};

mod input_selection;

mod encryption;
pub use encryption::EncryptCommand;

mod decryption;

mod editing;

mod keys;

mod config;

mod refresh;

test_binary::build_test_binary_once!(mock_editor, "test_bins");

mod command_utils;
pub use command_utils::{CommonArgs, OutputExitAssertions, OutputString, PackageCommand, RunCommand};

mod sops_references;
pub(crate) use sops_references::{sops_yaml_path, sops_yaml_str};
