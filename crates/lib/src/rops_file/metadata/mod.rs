mod core;
pub use core::{RopsFileMetadata, RopsFileMetadataDecryptError};

mod last_modified;
pub use last_modified::LastModifiedDateTime;

pub use state::{DecryptedMetadata, EncryptedMetadata, RopsMetadataState};
mod state {
    use std::{
        fmt::{Debug, Display},
        marker::PhantomData,
        str::FromStr,
    };

    use crate::*;

    pub trait RopsMetadataState {
        type Mac: Debug + PartialEq + FromStr + Display;
    }

    #[derive(Debug)]
    pub struct EncryptedMetadata<C: Cipher, H: Hasher>(PhantomData<C>, PhantomData<H>);
    impl<C: Cipher, H: Hasher> RopsMetadataState for EncryptedMetadata<C, H> {
        type Mac = EncryptedMac<C, H>;
    }

    #[derive(Debug)]
    pub struct DecryptedMetadata<H: Hasher>(PhantomData<H>);

    impl<H: Hasher> RopsMetadataState for DecryptedMetadata<H> {
        type Mac = Mac<H>;
    }

    mod private {
        use super::*;

        pub trait SealedRopsMetadataState {}
        impl<C: Cipher, H: Hasher> SealedRopsMetadataState for EncryptedMetadata<C, H> {}
        impl<H: Hasher> SealedRopsMetadataState for DecryptedMetadata<H> {}
    }
}

#[cfg(feature = "age")]
mod age;
#[cfg(feature = "age")]
pub use age::RopsFileAgeMetadata;
