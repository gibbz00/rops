use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::*;

#[derive(Default, Deserialize)]
pub struct Config {
    pub creation_rules: Vec<CreationRule>,
}

#[derive(Deserialize)]
pub struct CreationRule {
    #[serde(with = "serde_regex")]
    pub path_regex: Regex,
    pub integration_keys: IntegrationKeys,
}

impl Config {
    /// Order of retrieval:
    /// 1. Provided file path
    /// 2. By provided file path in environment variable (`$ROPS_CONFIG`)
    /// 3. File matching name `.rops.toml` in current dir or any ancestor thereof.
    /// 4. Fallback to default if none were found.
    pub fn retrieve(optional_config_path: Option<&Path>) -> anyhow::Result<Self> {
        super::retrieve::retrieve_impl::<Self>(optional_config_path)
    }
}
