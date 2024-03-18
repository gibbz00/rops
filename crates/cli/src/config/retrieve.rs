use std::path::Path;

use rops::file::format::*;
use serde::de::DeserializeOwned;

pub type DefaulConfigFileFormat = TomlFileFormat;
const ROPS_CONFIG_ENV_VAR_NAME: &str = "ROPS_CONFIG";
const ROPS_CONFIG_DEFAULT_FILE_NAME: &str = ".rops.toml";

// separated with generic parameter to simplify unit testing of strategy
pub(super) fn retrieve_impl<T: DeserializeOwned + Default>(optional_config_path: Option<&Path>) -> anyhow::Result<T> {
    if let Some(arg_path) = optional_config_path {
        return read_fs_path_and_deserialize::<T>(arg_path);
    }

    if let Some(env_path) = std::env::var_os(ROPS_CONFIG_ENV_VAR_NAME) {
        return read_fs_path_and_deserialize::<T>(env_path);
    }

    return traverse_fs_or_default::<T>();

    fn traverse_fs_or_default<T: DeserializeOwned + Default>() -> anyhow::Result<T> {
        let mut traversal_path = std::env::current_dir()?;
        loop {
            traversal_path.push(ROPS_CONFIG_DEFAULT_FILE_NAME);
            if traversal_path.exists() {
                return read_fs_path_and_deserialize::<T>(traversal_path);
            }
            traversal_path.pop();

            if !traversal_path.pop() {
                return Ok(T::default());
            }
        }
    }

    fn read_fs_path_and_deserialize<T: DeserializeOwned>(config_path: impl AsRef<Path>) -> anyhow::Result<T> {
        let config_string = std::fs::read_to_string(config_path)?;
        DefaulConfigFileFormat::deserialize_from_str(&config_string).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use tempfile::NamedTempFile;

    use super::*;

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    struct StubConfig {
        location: Location,
    }

    impl StubConfig {
        pub fn serialize(&self, path: &Path) {
            let config_string = DefaulConfigFileFormat::serialize_to_string(self).unwrap();
            std::fs::write(path, config_string).unwrap();
        }
    }

    #[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
    enum Location {
        Arg,
        Env,
        Traversal,
        #[default]
        Fallback,
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn retrieves_config_by_arg() {
        let expected_config = StubConfig { location: Location::Arg };
        let temp_file = NamedTempFile::new().unwrap();
        expected_config.serialize(temp_file.path());

        let retrieved_config = retrieve_impl(Some(temp_file.path())).unwrap();
        assert_eq!(expected_config, retrieved_config);
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn retrieves_config_by_env() {
        let expected_config = StubConfig { location: Location::Env };
        let temp_file = NamedTempFile::new().unwrap();
        expected_config.serialize(temp_file.path());

        std::env::set_var(ROPS_CONFIG_ENV_VAR_NAME, temp_file.path());

        let retrieved_config = retrieve_impl(None).unwrap();
        assert_eq!(expected_config, retrieved_config);

        std::env::remove_var(ROPS_CONFIG_ENV_VAR_NAME);
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn retrieves_config_by_traversal_in_current() {
        test_traversal_impl(&std::env::current_dir().unwrap())
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn retrieves_config_by_traversal_in_ancestor() {
        test_traversal_impl(std::env::current_dir().unwrap().parent().unwrap())
    }

    fn test_traversal_impl(directory_path: &Path) {
        let expected_config = StubConfig {
            location: Location::Traversal,
        };
        let path = directory_path.join(ROPS_CONFIG_DEFAULT_FILE_NAME);
        expected_config.serialize(&path);

        let retrieved_config = retrieve_impl(None).unwrap();
        assert_eq!(expected_config, retrieved_config);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    #[serial_test::serial(config_retrieval)]
    fn retrieves_config_by_default_fallback() {
        assert_eq!(StubConfig::default(), retrieve_impl(None).unwrap());
    }
}
