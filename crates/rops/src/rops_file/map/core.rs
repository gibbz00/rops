use derive_more::{Deref, DerefMut, From, Into};

use crate::*;

#[derive(PartialEq, From, Into, Deref, DerefMut)]
#[impl_tools::autoimpl(Debug)]
pub struct RopsMap<S: RopsMapState>(pub(crate) indexmap::IndexMap<String, RopsTree<S>>);

#[derive(PartialEq)]
#[impl_tools::autoimpl(Debug)]
pub enum RopsTree<S: RopsMapState> {
    Sequence(Vec<RopsTree<S>>),
    Map(RopsMap<S>),
    Null,
    Leaf(S::RopsTreeLeaf),
}

impl<C: Cipher> ToExternalMap<EncryptedMap<C>> for RopsMap<EncryptedMap<C>> {
    fn to_external<F: FileFormat>(self) -> RopsFileFormatMap<EncryptedMap<C>, F> {
        RopsFileFormatMap::from_inner_map(F::Map::encrypted_internal_to_format_map(self))
    }
}

impl ToExternalMap<DecryptedMap> for RopsMap<DecryptedMap> {
    fn to_external<F: FileFormat>(self) -> RopsFileFormatMap<DecryptedMap, F> {
        RopsFileFormatMap::from_inner_map(F::Map::decrypted_internal_to_format(self))
    }
}
