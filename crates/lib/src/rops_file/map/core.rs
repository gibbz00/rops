use std::{borrow::Cow, collections::HashMap};

use derive_more::{Deref, DerefMut, From, Into};

use crate::*;

#[derive(Debug, PartialEq, From, Into, Deref, DerefMut)]
pub struct RopsMap<S: RopsMapState>(pub(crate) indexmap::IndexMap<String, RopsTree<S>>);

#[derive(Debug, PartialEq)]
pub enum RopsTree<S: RopsMapState> {
    Sequence(Vec<RopsTree<S>>),
    Map(RopsMap<S>),
    Null,
    Leaf(S::RopsTreeLeaf),
}

// WORKAROUND: Non-cow tuple key doesn't allow saved_nounces.get((&key, &value))
#[derive(Debug, PartialEq, Deref, DerefMut)]
#[allow(clippy::complexity)]
pub struct SavedRopsMapNonces<C: Cipher>(pub(crate) HashMap<(Cow<'static, KeyPath>, Cow<'static, RopsValue>), Nonce<C::NonceSize>>);
