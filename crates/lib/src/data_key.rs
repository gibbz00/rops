use rand::RngCore;

pub struct DataKey;

impl DataKey {
    pub const SIZE: usize = 256;

    pub fn generate() -> [u8; Self::SIZE] {
        // Assumed to be cryptographically secure. Uses ChaCha12 as
        // the PRNG with OS provided RNG (e.g getrandom) for the
        // initial seed.
        //
        // https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html
        let mut rand = rand::thread_rng();

        let mut data_key = [0u8; Self::SIZE];
        rand.fill_bytes(&mut data_key);
        data_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_zeroed() {
        assert_ne!([0; DataKey::SIZE], DataKey::generate())
    }

    #[test]
    fn seemingly_random() {
        assert_ne!(DataKey::generate(), DataKey::generate())
    }
}
