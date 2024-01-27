use crate::*;

// TEMP: make into struct and derive Args once more fields are added.
pub type EditArgs = InputArgs;

impl MergeConfig for EditArgs {
    fn merge_config(&mut self, _config: Config) {
        // todo!()
    }
}
