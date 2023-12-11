pub use encoding::Base64EncodingUtils;
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

pub use decoding::Base64DecodingUtils;
mod decoding {
    use base64::{engine::general_purpose, DecodeError, Engine};

    pub trait Base64DecodingUtils {
        fn decode_base64(&mut self, base64_str: &str) -> Result<(), DecodeError>;
    }

    impl Base64DecodingUtils for Vec<u8> {
        fn decode_base64(&mut self, base64_str: &str) -> Result<(), DecodeError> {
            general_purpose::STANDARD_NO_PAD.decode_vec(base64_str.trim_end_matches('='), self)
        }
    }

    impl Base64DecodingUtils for [u8] {
        fn decode_base64(&mut self, base64_str: &str) -> Result<(), DecodeError> {
            general_purpose::STANDARD_NO_PAD
                .decode_slice_unchecked(base64_str.trim_end_matches('='), self.as_mut())
                .map(|_| ())
        }
    }
}
