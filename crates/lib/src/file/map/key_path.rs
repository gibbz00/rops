#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "test-utils", derive(derive_more::From))]
pub struct KeyPath(String);

impl KeyPath {
    pub fn join(&self, other: &str) -> Self {
        Self(format!("{}{}:", self.0, other))
    }

    pub fn last(&self) -> &str {
        self.0.strip_suffix(':').and_then(|str| str.split(':').next_back()).unwrap_or("")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gets_last_when_one_level() {
        let key_path = KeyPath::default().join("one");
        assert_eq!("one", key_path.last())
    }

    #[test]
    fn gets_last_when_multiple_levels() {
        let key_path = KeyPath::default().join("one").join("two");
        assert_eq!("two", key_path.last())
    }

    #[test]
    fn gets_last_when_empty() {
        assert_eq!("", KeyPath::default().last())
    }
}
