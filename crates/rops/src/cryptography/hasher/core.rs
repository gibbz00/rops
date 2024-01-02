use generic_array::{ArrayLength, GenericArray};

pub trait Hasher: private::SealedHasher {
    type OutputSize: ArrayLength<u8>;

    fn new() -> Self;

    fn update(&mut self, input: impl AsRef<[u8]>);

    fn finalize(self) -> GenericArray<u8, Self::OutputSize>;
}

mod private {
    pub trait SealedHasher {}

    #[cfg(feature = "sha2")]
    impl SealedHasher for crate::SHA512 {}
}
