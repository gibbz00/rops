use derive_more::Deref;

#[derive(Deref)]
#[cfg_attr(feature = "test-utils", derive(derive_more::From))]
pub struct KeyPath(String);
