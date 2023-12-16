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

        impl MockTestUtil for RopsFileMap<Decrypted, YamlFileFormat> {
            fn mock() -> Self {
                serde_yaml::from_str(&Self::mock_format_display()).expect("mock yaml string not serializable")
            }
        }
    }
}
