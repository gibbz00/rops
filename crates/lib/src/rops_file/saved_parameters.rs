use crate::*;

#[derive(Debug)]
#[impl_tools::autoimpl(PartialEq)]
pub struct SavedParameters<C: Cipher, H: Hasher> {
    pub(crate) data_key: DataKey,
    pub(crate) saved_map_nonces: SavedRopsMapNonces<C>,
    pub(crate) saved_mac_nonce: SavedMacNonce<C, H>,
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<C: Cipher, H: Hasher> MockTestUtil for SavedParameters<C, H>
    where
        SavedRopsMapNonces<C>: MockTestUtil,
        SavedMacNonce<C, H>: MockTestUtil,
    {
        fn mock() -> Self {
            Self {
                data_key: DataKey::mock(),
                saved_map_nonces: SavedRopsMapNonces::mock(),
                saved_mac_nonce: SavedMacNonce::mock(),
            }
        }
    }
}
