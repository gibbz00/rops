use generic_array::ArrayLength;

use crate::*;

// IMPROVEMENT: replace with generic array
const INITIAL_VALUE_SIZE: usize = 32;

#[derive(Debug, PartialEq, Default)]
pub struct InitialValue<T: ArrayLength<u8>>(RngKey<T>);

impl<T: ArrayLength<u8>> InitialValue<T> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(RngKey::new())
    }
}

// TEMP(WORKAROUND): derive_more::AsRef doesn't seem to work
impl<T: ArrayLength<u8>> AsRef<[u8]> for InitialValue<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// TEMP(WORKAROUND): derive_more::AsMut doesn't seem to work
impl<T: ArrayLength<u8>> AsMut<[u8]> for InitialValue<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use generic_array::{typenum::U32, GenericArray};

    use super::*;

    impl MockTestUtil for InitialValue<U32> {
        fn mock() -> Self {
            Self(
                GenericArray::from([
                    147, 11, 85, 58, 78, 46, 255, 2, 199, 50, 139, 199, 96, 109, 167, 128, 187, 254, 184, 207, 20, 245, 66, 107, 35, 24,
                    210, 235, 48, 138, 153, 86,
                ])
                .into(),
            )
        }
    }

    impl MockDisplayTestUtil for InitialValue<U32> {
        fn mock_display() -> String {
            "kwtVOk4u/wLHMovHYG2ngLv+uM8U9UJrIxjS6zCKmVY=".to_string()
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
