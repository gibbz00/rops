#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "test-utils", derive(derive_more::From))]
pub struct KeyPath(String);

impl KeyPath {
    pub fn join(&self, other: &str) -> Self {
        Self(format!("{}{}:", self.0, other))
    }
}

impl AsRef<[u8]> for KeyPath {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use crate::*;

    impl MockTestUtil for KeyPath {
        fn mock() -> Self {
            Self("hello:".to_string())
        }
    }
}
