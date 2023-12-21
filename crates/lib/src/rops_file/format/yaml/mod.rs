use crate::*;

#[derive(Debug, PartialEq)]
pub struct YamlFileFormat;

impl FileFormat for YamlFileFormat {
    type Map = serde_yaml::Mapping;
    type SerializeError = serde_yaml::Error;
    type DeserializeError = serde_yaml::Error;

    fn serialize_to_string<T: serde::Serialize>(t: &T) -> Result<String, Self::SerializeError> {
        serde_yaml::to_string(t)
    }

    fn deserialize_from_str<T: serde::de::DeserializeOwned>(str: &str) -> Result<T, Self::DeserializeError> {
        serde_yaml::from_str(str)
    }
}

mod transforms;

#[cfg(feature = "test-utils")]
mod mock;

#[cfg(test)]
mod tests;
