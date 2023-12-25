use derive_more::{AsMut, AsRef};
use generic_array::typenum::{Unsigned, U32};

use crate::*;

type DataKeySize = U32;

// FIXME: zeroize upon drop?
#[derive(Debug, PartialEq, AsRef, AsMut)]
#[as_ref(forward)]
#[as_mut(forward)]
pub struct DataKey(RngKey<DataKeySize>);

impl DataKey {
    pub const fn byte_size() -> usize {
        DataKeySize::USIZE
    }

    pub fn empty() -> Self {
        Self(RngKey::empty())
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use generic_array::GenericArray;

    use crate::*;

    impl MockTestUtil for DataKey {
        fn mock() -> Self {
            Self(
                GenericArray::from([
                    254, 79, 93, 103, 195, 165, 169, 238, 35, 187, 236, 95, 222, 243, 40, 26, 130, 128, 59, 176, 15, 195, 55, 93, 129, 212,
                    57, 80, 15, 181, 72, 114,
                ])
                .into(),
            )
        }
    }
}
