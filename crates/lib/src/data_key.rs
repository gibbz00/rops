use rand::RngCore;

const DATA_KEY_SIZE: usize = 256;

#[derive(Debug, PartialEq)]
pub struct DataKey([u8; DATA_KEY_SIZE]);

impl DataKey {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // Assumed to be cryptographically secure. Uses ChaCha12 as
        // the PRNG with OS provided RNG (e.g getrandom) for the
        // initial seed.
        //
        // https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
        let mut rand = rand::thread_rng();

        let mut inner = [0u8; DATA_KEY_SIZE];
        rand.fill_bytes(&mut inner);
        Self(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_zeroed() {
        assert_ne!([0; DATA_KEY_SIZE], DataKey::new().0)
    }

    #[test]
    fn seemingly_random() {
        assert_ne!(DataKey::new(), DataKey::new())
    }
}
