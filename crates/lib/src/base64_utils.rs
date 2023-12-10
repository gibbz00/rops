use base64::{engine::general_purpose, Engine};

pub trait Base64Utils
where
    Self: AsRef<[u8]>,
{
    fn encode_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.as_ref())
    }

    fn decode_base64(&self) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::STANDARD.decode(self.as_ref())
    }
}

impl<T: AsRef<[u8]>> Base64Utils for T {}
