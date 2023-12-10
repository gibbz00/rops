use derive_more::{AsMut, AsRef};

use crate::*;

const DATA_KEY_SIZE: usize = 32;

// FIXME: zeroize upon drop?
#[derive(Debug, PartialEq, AsRef, AsMut)]
#[as_ref(forward)]
#[as_mut(forward)]
pub struct DataKey(RngKey<DATA_KEY_SIZE>);

impl DataKey {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(RngKey::new())
    }

    pub const fn empty() -> Self {
        Self(RngKey::empty())
    }

    pub const fn byte_size() -> usize {
        RngKey::<{ DATA_KEY_SIZE }>::byte_size()
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use crate::*;

    impl MockTestUtil for DataKey {
        fn mock() -> Self {
            Self(
                [
                    254, 79, 93, 103, 195, 165, 169, 238, 35, 187, 236, 95, 222, 243, 40, 26, 130, 128, 59, 176, 15, 195, 55, 93, 129, 212,
                    57, 80, 15, 181, 72, 114,
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
    fn data_key_is_256_bits() {
        assert_eq!(256, DATA_KEY_SIZE * 8)
    }
}
