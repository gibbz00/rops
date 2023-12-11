use serde::{de::DeserializeOwned, Serialize};

pub trait FileFormat {
    type Map;
    type SerializeError: std::error::Error + Send + Sync + 'static;
    type DeserializeError: std::error::Error + Send + Sync + 'static;

    fn serialize_to_string<T: Serialize>(t: &T) -> Result<String, Self::SerializeError>;
    fn deserialize_from_str<T: DeserializeOwned>(str: &str) -> Result<T, Self::DeserializeError>;
}
