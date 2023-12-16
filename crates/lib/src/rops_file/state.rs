pub trait RopsFileState: sealed::SeleadRopsFileState {}
impl<S: sealed::SeleadRopsFileState> RopsFileState for S {}

#[derive(Debug, PartialEq)]
pub struct Encrypted;
#[derive(Debug, PartialEq)]
pub struct Decrypted;

mod sealed {
    use super::*;

    pub trait SeleadRopsFileState {}

    impl SeleadRopsFileState for Encrypted {}
    impl SeleadRopsFileState for Decrypted {}
}
