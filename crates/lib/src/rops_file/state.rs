use std::marker::PhantomData;

use crate::*;

pub trait RopsFileState {
    type RopsTreeLeaf;
}

#[derive(Debug, PartialEq)]
pub struct Encrypted<C: Cipher>(PhantomData<C>);
impl<C: Cipher> RopsFileState for Encrypted<C> {
    type RopsTreeLeaf = EncryptedRopsValue<C>;
}

#[derive(Debug, PartialEq)]
pub struct Decrypted;
impl RopsFileState for Decrypted {
    type RopsTreeLeaf = RopsValue;
}
