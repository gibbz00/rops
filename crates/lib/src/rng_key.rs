use derive_more::{AsMut, AsRef};
use rand::RngCore;

#[derive(Debug, PartialEq, AsRef, AsMut)]
pub struct RngKey<const BYTE_SIZE: usize>([u8; BYTE_SIZE]);

impl<const BYTE_SIZE: usize> RngKey<BYTE_SIZE> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // Assumed to be cryptographically secure. Uses ChaCha12 as
        // the PRNG with OS provided RNG (e.g getrandom) for the
        // initial seed.
        //
        // https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
        let mut rand = rand::thread_rng();

        let mut inner = [0u8; BYTE_SIZE];
        rand.fill_bytes(&mut inner);
        Self(inner)
    }

    pub const fn byte_size() -> usize {
        BYTE_SIZE
    }

    pub const fn empty() -> Self {
        Self([0; BYTE_SIZE])
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl<const BYTESIZE: usize> From<[u8; BYTESIZE]> for RngKey<BYTESIZE> {
        fn from(bytes: [u8; BYTESIZE]) -> Self {
            Self(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_BYTE_SIZE: usize = 32;
    type MockRngKey = RngKey<{ MOCK_BYTE_SIZE }>;

    #[test]
    fn new_rng_key_not_zeroed() {
        assert_ne!(&[0; MOCK_BYTE_SIZE], MockRngKey::new().as_ref())
    }

    #[test]
    fn new_rng_key_seems_random() {
        assert_ne!(MockRngKey::new(), MockRngKey::new())
    }
}
