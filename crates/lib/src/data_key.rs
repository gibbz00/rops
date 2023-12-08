use rand::RngCore;

pub const DATA_KEY_BYTE_SIZE: usize = 32;

// FIXME: zeroize upon drop?
#[derive(Debug, PartialEq)]
pub struct DataKey([u8; DATA_KEY_BYTE_SIZE]);

impl DataKey {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // Assumed to be cryptographically secure. Uses ChaCha12 as
        // the PRNG with OS provided RNG (e.g getrandom) for the
        // initial seed.
        //
        // https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
        let mut rand = rand::thread_rng();

        let mut inner = [0u8; DATA_KEY_BYTE_SIZE];
        rand.fill_bytes(&mut inner);
        Self(inner)
    }

    pub fn empty() -> Self {
        Self([0; DATA_KEY_BYTE_SIZE])
    }
}

impl AsRef<[u8]> for DataKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for DataKey {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

#[cfg(feature = "test-utils")]
mod test_utils {
    use crate::*;

    impl MockTestUtil for DataKey {
        fn mock() -> Self {
            Self([
                67, 11, 25, 39, 242, 246, 79, 131, 60, 80, 226, 83, 115, 116, 50, 131, 39, 148, 220, 226, 136, 158, 165, 19, 155, 218, 16,
                53, 47, 24, 192, 26,
            ])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_key_is_256_bits() {
        assert_eq!(256, DATA_KEY_BYTE_SIZE * 8)
    }

    #[test]
    fn new_data_key_not_zeroed() {
        assert_ne!([0; DATA_KEY_BYTE_SIZE], DataKey::new().as_ref())
    }

    #[test]
    fn seemingly_random() {
        assert_ne!(DataKey::new(), DataKey::new())
    }
}
