pub use core::Hasher;
mod core {
    use generic_array::{ArrayLength, GenericArray};

    pub trait Hasher {
        type OutputSize: ArrayLength<u8>;

        fn new() -> Self;

        fn update(&mut self, input: impl AsRef<[u8]>);

        fn finalize(self) -> GenericArray<u8, Self::OutputSize>;
    }
}

#[cfg(feature = "sha2")]
pub use sha512::SHA512;
#[cfg(feature = "sha2")]
mod sha512 {
    use sha2::{digest::OutputSizeUser, Digest, Sha512};

    use crate::*;

    #[derive(Debug)]
    pub struct SHA512(Sha512);

    impl Hasher for SHA512 {
        type OutputSize = <Sha512 as OutputSizeUser>::OutputSize;

        fn new() -> Self {
            Self(Sha512::new())
        }

        fn update(&mut self, input: impl AsRef<[u8]>) {
            self.0.update(input)
        }

        fn finalize(self) -> generic_array::GenericArray<u8, Self::OutputSize> {
            self.0.finalize()
        }
    }
}
