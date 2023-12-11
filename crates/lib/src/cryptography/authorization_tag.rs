use std::str::FromStr;

use derive_more::{AsMut, AsRef, From};
use generic_array::GenericArray;

use crate::*;

#[derive(Debug, PartialEq, AsRef, AsMut, From)]
#[as_mut(forward)]
#[as_ref(forward)]
pub struct AuthorizationTag<C: AeadCipher>(GenericArray<u8, C::AuthorizationTagSize>);

impl<C: AeadCipher> FromStr for AuthorizationTag<C> {
    type Err = Base64DecodeError;

    fn from_str(base64_str: &str) -> Result<Self, Self::Err> {
        let mut buffer = Self(GenericArray::default());
        buffer.as_mut().decode_base64(base64_str).map(|_| buffer)
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use crate::*;

        impl MockTestUtil for AuthorizationTag<AES256GCM> {
            fn mock() -> Self {
                Self([157, 5, 3, 146, 232, 116, 57, 29, 92, 141, 30, 97, 24, 46, 99, 59].into())
            }
        }

        impl<C: AeadCipher> MockDisplayTestUtil for AuthorizationTag<C> {
            fn mock_display() -> String {
                "nQUDkuh0OR1cjR5hGC5jOw==".to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "aes-gcm")]
    mod aes_gcm {
        use crate::*;

        #[test]
        fn parses_base64_str() {
            FromStrTestUtils::assert_parse::<AuthorizationTag<AES256GCM>>()
        }
    }
}
