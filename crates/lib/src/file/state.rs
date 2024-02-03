pub(crate) use core::RopsFileState;
mod core {
    use crate::*;

    pub trait RopsFileState: private::SealedRopsFileState {
        type MapState: RopsMapState;
        type MetadataState: RopsMetadataState;
    }

    mod private {
        use super::*;

        pub trait SealedRopsFileState {}
        impl<C: Cipher, H: Hasher> SealedRopsFileState for EncryptedFile<C, H> {}
        impl<H: Hasher> SealedRopsFileState for DecryptedFile<H> {}
    }
}

pub use encrypted::EncryptedFile;
mod encrypted {
    use std::marker::PhantomData;

    use crate::*;

    pub struct EncryptedFile<C: Cipher, H: Hasher>(PhantomData<C>, PhantomData<H>);
    impl<C: Cipher, H: Hasher> RopsFileState for EncryptedFile<C, H> {
        type MapState = EncryptedMap<C>;
        type MetadataState = EncryptedMetadata<C, H>;
    }
}

pub use decrypted::DecryptedFile;
mod decrypted {
    use std::marker::PhantomData;

    use crate::*;

    pub struct DecryptedFile<H: Hasher>(PhantomData<H>);
    impl<H: Hasher> RopsFileState for DecryptedFile<H> {
        type MapState = DecryptedMap;
        type MetadataState = DecryptedMetadata<H>;
    }
}
