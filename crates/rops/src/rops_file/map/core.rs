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
