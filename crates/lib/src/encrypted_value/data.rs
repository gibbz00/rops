use derive_more::AsRef;

use crate::*;

#[derive(Debug, PartialEq)]
pub struct EncryptedValueData(Vec<u8>);

#[derive(AsRef)]
#[as_ref(forward)]
pub struct EncryptedValueDataAuthorizationTag<'a>(&'a [u8]);

#[derive(AsRef)]
#[as_ref(forward)]
pub struct EncryptedValueDataExceptTag<'a>(&'a [u8]);

impl EncryptedValueData {
    pub fn tag(&self, cipher: &dyn Cipher) -> EncryptedValueDataAuthorizationTag {
        EncryptedValueDataAuthorizationTag(&self.0[self.cipher_authorization_tag_start_index(cipher)..])
    }

    pub fn except_tag(&self, cipher: &dyn Cipher) -> EncryptedValueDataExceptTag {
        EncryptedValueDataExceptTag(&self.0[..self.cipher_authorization_tag_start_index(cipher)])
    }

    fn cipher_authorization_tag_start_index(&self, cipher: &dyn Cipher) -> usize {
        self.0
            .len()
            .checked_sub(cipher.authorization_tag_size())
            .expect("minimum encrypted value length less than cipher authorization tag size")
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockStringTestUtil for EncryptedValueDataExceptTag<'_> {
        fn mock_string() -> String {
            "3S1E9am/".to_string()
        }
    }

    impl MockStringTestUtil for EncryptedValueDataAuthorizationTag<'_> {
        fn mock_string() -> String {
            "nQUDkuh0OR1cjR5hGC5jOw==".to_string()
        }
    }

    impl MockTestUtil for EncryptedValueData {
        fn mock() -> Self {
            Self(vec![
                221, 45, 68, 245, 169, 191, 157, 5, 3, 146, 232, 116, 57, 29, 92, 141, 30, 97, 24, 46, 99, 59,
            ])
        }
    }
}
