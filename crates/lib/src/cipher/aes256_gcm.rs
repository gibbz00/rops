use crate::*;

pub struct AES256GCM;

impl Cipher for AES256GCM {
    fn authorization_tag_size(&self) -> usize {
        16
    }
}
