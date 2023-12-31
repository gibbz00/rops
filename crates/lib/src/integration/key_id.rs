use std::{fmt::Debug, hash::Hash};

use crate::*;

pub trait IntegrationKeyId<I: Integration>: Debug + PartialEq + Eq + Hash {
    fn append_to_builder<F: FileFormat>(self, rops_file_builder: &mut RopsFileBuilder<F>);
}
