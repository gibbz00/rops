pub(crate) use error::Base64DecodeError;
mod error {
    #[derive(Debug, thiserror::Error)]
    #[error("unable to base64 decode {0}, reason: {1}")]
    pub struct Base64DecodeError(pub String, pub base64::DecodeError);
}

pub(crate) use encoding::Base64EncodingUtils;
mod encoding {
    use base64::{engine::general_purpose, Engine};

    pub trait Base64EncodingUtils
    where
        Self: AsRef<[u8]>,
    {
        fn encode_base64(&self) -> String {
            general_purpose::STANDARD.encode(self.as_ref())
        }
    }

    impl<T: AsRef<[u8]>> Base64EncodingUtils for T {}
}

pub(crate) use decoding::Base64DecodingUtils;
mod decoding {
    use base64::{engine::general_purpose, Engine};

    use crate::*;

    pub trait Base64DecodingUtils {
        fn decode_base64(&mut self, base64_str: &str) -> Result<(), Base64DecodeError>;
    }

    impl Base64DecodingUtils for Vec<u8> {
        fn decode_base64(&mut self, base64_str: &str) -> Result<(), Base64DecodeError> {
            general_purpose::STANDARD_NO_PAD
                .decode_vec(base64_str.trim_end_matches('='), self)
                .map_err(|reason| Base64DecodeError(base64_str.to_string(), reason))
        }
    }

    impl Base64DecodingUtils for [u8] {
        fn decode_base64(&mut self, base64_str: &str) -> Result<(), Base64DecodeError> {
            general_purpose::STANDARD_NO_PAD
                .decode_slice_unchecked(base64_str.trim_end_matches('='), self.as_mut())
                .map(|_| ())
                .map_err(|reason| Base64DecodeError(base64_str.to_string(), reason))
        }
    }
}
