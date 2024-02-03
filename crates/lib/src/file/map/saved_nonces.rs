use std::{borrow::Cow, collections::HashMap};

use crate::*;

/// Nonce store that is supposed to only be used when both keypaths and values match.
#[derive(Debug)]
#[impl_tools::autoimpl(PartialEq, Default)]
#[allow(clippy::complexity)]
// WORKAROUND: Non-cow tuple key doesn't allow saved_nounces.get((&key, &value))
pub struct SavedRopsMapNonces<C: Cipher>(HashMap<(Cow<'static, KeyPath>, Cow<'static, RopsValue>), Nonce<C::NonceSize>>);

impl<C: Cipher> SavedRopsMapNonces<C> {
    pub fn insert(&mut self, key: (KeyPath, RopsValue), value: Nonce<C::NonceSize>) {
        self.0.insert((Cow::Owned(key.0), Cow::Owned(key.1)), value);
    }

    pub fn get<'a>(&'a self, key: (&'a KeyPath, &'a RopsValue)) -> Option<&'a Nonce<C::NonceSize>> {
        self.0.get(&(Cow::Borrowed(key.0), Cow::Borrowed(key.1)))
    }
}
