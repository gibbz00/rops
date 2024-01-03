use std::marker::PhantomData;

use crate::*;

pub trait RopsFileState: private::SealedRopsFileState {
    type MapState: RopsMapState;
    type MetadataState: RopsMetadataState;
}

pub struct EncryptedFile<C: Cipher, H: Hasher>(PhantomData<C>, PhantomData<H>);
impl<C: Cipher, H: Hasher> RopsFileState for EncryptedFile<C, H> {
    type MapState = EncryptedMap<C>;
    type MetadataState = EncryptedMetadata<C, H>;
}

pub struct DecryptedFile<H: Hasher>(PhantomData<H>);
impl<H: Hasher> RopsFileState for DecryptedFile<H> {
    type MapState = DecryptedMap;
    type MetadataState = DecryptedMetadata<H>;
}

mod private {
    use super::*;

    pub trait SealedRopsFileState {}
    impl<C: Cipher, H: Hasher> SealedRopsFileState for EncryptedFile<C, H> {}
    impl<H: Hasher> SealedRopsFileState for DecryptedFile<H> {}
}
