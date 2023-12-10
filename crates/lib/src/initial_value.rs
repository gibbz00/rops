use crate::*;

const INITIAL_VALUE_SIZE: usize = 32;

#[derive(Debug, PartialEq)]
pub struct InitialValue(RngKey<INITIAL_VALUE_SIZE>);

impl InitialValue {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(RngKey::new())
    }

    pub const fn byte_size() -> usize {
        RngKey::<{ INITIAL_VALUE_SIZE }>::byte_size()
    }
}

// TEMP(WORKAROUND): derive_more::AsRef doesn't seem to work
impl AsRef<[u8]> for InitialValue {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for InitialValue {
        fn mock() -> Self {
            Self(
                [
                    147, 11, 85, 58, 78, 46, 255, 2, 199, 50, 139, 199, 96, 109, 167, 128, 187, 254, 184, 207, 20, 245, 66, 107, 35, 24,
                    210, 235, 48, 138, 153, 86,
                ]
                .into(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_value_is_256_bits() {
        assert_eq!(256, INITIAL_VALUE_SIZE * 8)
    }
}
