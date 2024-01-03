use crate::*;

#[impl_tools::autoimpl(Debug, PartialEq)]
pub struct SavedMacNonce<C: Cipher, H: Hasher>(Mac<H>, Nonce<C::NonceSize>);

impl<C: Cipher, H: Hasher> SavedMacNonce<C, H> {
    pub fn new(mac: Mac<H>, nonce: Nonce<C::NonceSize>) -> Self {
        Self(mac, nonce)
    }

    pub fn get_or_create(self, mac: &Mac<H>) -> Nonce<C::NonceSize> {
        match &self.0 == mac {
            true => self.1,
            false => Nonce::new(),
        }
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<C: Cipher, H: Hasher> MockTestUtil for SavedMacNonce<C, H>
    where
        Mac<H>: MockTestUtil,
        EncryptedMac<C, H>: MockTestUtil,
    {
        fn mock() -> Self {
            Self::new(Mac::mock(), EncryptedMac::<C, H>::mock().0.nonce)
        }
    }
}
