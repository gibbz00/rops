use derive_more::Deref;

#[derive(Deref)]
#[cfg_attr(feature = "test-utils", derive(derive_more::From))]
pub struct KeyPath(String);

#[cfg(feature = "test-utils")]
mod mock {
    use crate::*;

    impl MockTestUtil for KeyPath {
        fn mock() -> Self {
            Self("hello:".to_string())
        }
    }
}
