use crate::*;

#[derive(Debug, PartialEq)]
pub enum RopsTree<S: RopsFileState> {
    Sequence(Vec<RopsTree<S>>),
    Map(indexmap::IndexMap<String, RopsTree<S>>),
    Null,
    Leaf(S::RopsTreeLeaf),
}
