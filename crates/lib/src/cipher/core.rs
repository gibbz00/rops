pub trait Cipher {
    fn authorization_tag_size(&self) -> usize;
}
