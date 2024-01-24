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
