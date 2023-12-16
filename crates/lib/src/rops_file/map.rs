use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RopsFileMap<S: RopsFileState, F: FileFormat> {
    #[serde(flatten)]
    inner: F::Map,
    #[serde(skip)]
    state_marker: PhantomData<S>,
}

impl<S: RopsFileState, F: FileFormat> RopsFileMap<S, F> {
    pub fn into_inner_map(self) -> F::Map {
        self.inner
    }

    #[cfg(feature = "test-utils")]
    pub fn from_inner_map(inner: F::Map) -> Self {
        Self {
            inner,
            state_marker: PhantomData,
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    #[cfg(feature = "yaml")]
    mod yaml {
        use crate::*;

        impl MockFileFormatUtil<YamlFileFormat> for RopsFileMap<Decrypted, YamlFileFormat> {
            fn mock_format_display() -> String {
                indoc::indoc! {"
                hello: world!
                nested_map:
                  null_key: null
                  array:
                  - string
                  - nested_map_in_array:
                      integer: 1234
                  - float: 1234.56789
                booleans:
                - true
                - false"
                }
                .to_string()
            }
        }

        #[cfg(feature = "aes-gcm")]
        impl MockFileFormatUtil<YamlFileFormat> for RopsFileMap<Encrypted<AES256GCM>, YamlFileFormat> {
            fn mock_format_display() -> String {
                indoc::indoc! {"
                    hello: ENC[AES256_GCM,data:3S1E9am/,iv:WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=,tag:nQUDkuh0OR1cjR5hGC5jOw==,type:str]
                    nested_map:
                      null_key: null
                      array:
                      - ENC[AES256_GCM,data:ANbeNrGp,iv:PRWGCPdOttPr5dlzT9te7WWCZ90J7+CvfY1vp60aADM=,tag:PvSLx4pLT5zRKOU0df8Xlg==,type:str]
                      - nested_map_in_array:
                          integer: ENC[AES256_GCM,data:qTW5qw==,iv:ugMxvR8YPwDgn2MbBpDX0lpCqzJY3GerhbA5jEKUbwE=,tag:d8utfA76C4XPzJyDfgE4Pw==,type:int]
                      - float: ENC[AES256_GCM,data:/MTg0fCennyN8g==,iv:+/8+Ljm+cls7BbDYZnlg6NVFkrkw4GkEfWU2aGW57qE=,tag:26uMp2JmVAckySIaL2BLCg==,type:float]
                    booleans:
                    - ENC[AES256_GCM,data:bCdz2A==,iv:8kD+h1jClyVHBj9o2WZuAkjk+uD6A2lgNpcGljpQEhk=,tag:u3/fktl5HfFrVLERVvLRGw==,type:bool]
                    - ENC[AES256_GCM,data:SgBh7wY=,iv:0s9Q9pQWbsZm2yHsmFalCzX0IqNb6ZqeY6QQYCWc+qU=,tag:OZb76BWCKbDLbcil4c8fYA==,type:bool]"
                }
                .to_string()
            }
        }

        impl<S: RopsFileState> MockTestUtil for RopsFileMap<S, YamlFileFormat>
        where
            Self: MockFileFormatUtil<YamlFileFormat>,
        {
            fn mock() -> Self {
                serde_yaml::from_str(&Self::mock_format_display()).expect("mock yaml string not serializable")
            }
        }
    }
}
