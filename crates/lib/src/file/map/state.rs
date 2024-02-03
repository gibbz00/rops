pub(crate) use core::RopsMapState;
mod core {
    use std::fmt::Debug;

    use crate::*;

    pub trait RopsMapState: private::SealedRopsMapState {
        type RopsTreeLeaf: Debug + PartialEq;
    }

    mod private {
        use super::*;

        pub trait SealedRopsMapState {}
        impl<C: Cipher> SealedRopsMapState for EncryptedMap<C> {}
        impl SealedRopsMapState for DecryptedMap {}
    }
}

pub use encrypted::EncryptedMap;
pub(crate) use encrypted::RopsMapEncryptedLeaf;
mod encrypted {
    use std::marker::PhantomData;

    use crate::*;

    pub struct EncryptedMap<C: Cipher>(PhantomData<C>);

    impl<C: Cipher> RopsMapState for EncryptedMap<C> {
        type RopsTreeLeaf = RopsMapEncryptedLeaf<C>;
    }

    #[impl_tools::autoimpl(Debug, PartialEq)]
    pub enum RopsMapEncryptedLeaf<C: Cipher> {
        Encrypted(EncryptedRopsValue<C>),
        Escaped(RopsValue),
    }
}

pub use decrypted::DecryptedMap;
mod decrypted {
    use crate::*;

    pub struct DecryptedMap;
    impl RopsMapState for DecryptedMap {
        type RopsTreeLeaf = RopsValue;
    }
}
