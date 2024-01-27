use std::path::Path;

use crate::*;

pub trait ConfigArg {
    fn config_path(&self) -> Option<&Path>;
}

pub trait MergeConfig {
    fn merge_config(&mut self, config: Config);
}
