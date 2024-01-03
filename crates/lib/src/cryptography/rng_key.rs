use derive_more::{AsMut, AsRef};
use generic_array::{ArrayLength, GenericArray};
use rand::RngCore;

// IMPROVEMENT: replace with generic array
#[derive(Debug, Clone, PartialEq, AsRef, AsMut)]
#[as_ref(forward)]
pub struct RngKey<T: ArrayLength<u8>>(pub(crate) GenericArray<u8, T>);

impl<T: ArrayLength<u8>> RngKey<T> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // Assumed to be cryptographically secure. Uses ChaCha12 as
        // the PRNG with OS provided RNG (e.g getrandom) for the
        // initial seed.
        //
        // https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
        let mut rand = rand::thread_rng();

        let mut inner = GenericArray::default();
        rand.fill_bytes(&mut inner);
        Self(inner)
    }

    pub fn empty() -> Self {
        Self(GenericArray::default())
    }
}

#[cfg(test)]
mod tests {
    use generic_array::typenum::Unsigned;

    use super::*;

    type MockArrayLength = generic_array::typenum::U32;
    type MockRngKey = RngKey<MockArrayLength>;

    #[test]
    fn new_rng_key_not_zeroed() {
        assert_ne!(&[0; MockArrayLength::USIZE], MockRngKey::new().0.as_slice())
    }

    #[test]
    fn new_rng_key_seems_random() {
        assert_ne!(MockRngKey::new(), MockRngKey::new())
    }
}
