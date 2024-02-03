pub(crate) use core::RopsMetadataState;
mod core {
    use std::{
        fmt::{Debug, Display},
        str::FromStr,
    };

    use crate::*;

    pub trait RopsMetadataState {
        type Mac: Debug + PartialEq + FromStr + Display;
    }

    mod private {
        use super::*;

        pub trait SealedRopsMetadataState {}
        impl<C: Cipher, H: Hasher> SealedRopsMetadataState for EncryptedMetadata<C, H> {}
        impl<H: Hasher> SealedRopsMetadataState for DecryptedMetadata<H> {}
    }
}

pub use encrypted::EncryptedMetadata;
mod encrypted {
    use std::marker::PhantomData;

    use crate::*;

    pub struct EncryptedMetadata<C: Cipher, H: Hasher>(PhantomData<C>, PhantomData<H>);

    impl<C: Cipher, H: Hasher> RopsMetadataState for EncryptedMetadata<C, H> {
        type Mac = EncryptedMac<C, H>;
    }
}

pub use decrypted::DecryptedMetadata;
mod decrypted {
    use std::marker::PhantomData;

    use crate::*;
    pub struct DecryptedMetadata<H: Hasher>(PhantomData<H>);

    impl<H: Hasher> RopsMetadataState for DecryptedMetadata<H> {
        type Mac = Mac<H>;
    }
}
