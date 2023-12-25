use std::{fmt::Debug, marker::PhantomData};

use crate::*;

pub trait RopsMapState: private::SealedRopsMapState {
    type RopsTreeLeaf: Debug + PartialEq;
}

#[derive(Debug, PartialEq)]
pub struct EncryptedMap<C: Cipher>(PhantomData<C>);
impl<C: Cipher> RopsMapState for EncryptedMap<C> {
    type RopsTreeLeaf = EncryptedRopsValue<C>;
}

#[derive(Debug, PartialEq)]
pub struct DecryptedMap;
impl RopsMapState for DecryptedMap {
    type RopsTreeLeaf = RopsValue;
}

mod private {
    use super::*;

    pub trait SealedRopsMapState {}
    impl<C: Cipher> SealedRopsMapState for EncryptedMap<C> {}
    impl SealedRopsMapState for DecryptedMap {}
}
