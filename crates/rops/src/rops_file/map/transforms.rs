use crate::*;

pub trait ToExternalMap<S: RopsMapState> {
    fn to_external<F: FileFormat>(self) -> RopsFileFormatMap<S, F>;
}
