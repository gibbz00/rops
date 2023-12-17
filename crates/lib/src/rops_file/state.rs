use std::{fmt::Debug, marker::PhantomData};

use crate::*;

pub trait RopsFileState: Debug + PartialEq {
    type RopsTreeLeaf: Debug + PartialEq;
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
