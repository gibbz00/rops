use std::fmt::Debug;

use generic_array::ArrayLength;

pub trait Cipher {
    type AuthorizationTagSize: ArrayLength + Debug + PartialEq;
    const NAME: &'static str;
}
