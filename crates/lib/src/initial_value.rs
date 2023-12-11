use generic_array::{typenum::U32, ArrayLength};

use crate::*;

#[derive(Debug, PartialEq, Default)]
pub struct InitialValue<T: ArrayLength<u8> = U32>(RngKey<T>);

impl<T: ArrayLength<u8>> InitialValue<T> {
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
    use generic_array::GenericArray;

    use super::*;

    impl MockTestUtil for InitialValue {
        fn mock() -> Self {
            Self(
                GenericArray::from([
                    89, 68, 40, 65, 58, 209, 95, 15, 237, 82, 12, 41, 153, 33, 186, 247, 21, 173, 119, 151, 85, 49, 247, 188, 169, 73, 114,
                    213, 80, 124, 185, 195,
                ])
                .into(),
            )
        }
    }

    impl MockDisplayTestUtil for InitialValue {
        fn mock_display() -> String {
            "WUQoQTrRXw/tUgwpmSG69xWtd5dVMfe8qUly1VB8ucM=".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_values_match() {
        let mut initial_value = InitialValue::default();
        initial_value.as_mut().decode_base64(&InitialValue::mock_display()).unwrap();
        assert_eq!(InitialValue::mock(), initial_value)
    }
}
