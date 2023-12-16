use crate::*;

#[derive(Debug, thiserror::Error)]
pub enum RopsFileDecryptError {
    #[error("invalid map: {0}")]
    MapToTree(#[from] MapToTreeError),
}

impl<C: AeadCipher, F: FileFormat> RopsFile<Encrypted<C>, F> {
    pub fn decrypt(self) -> Result<(), RopsFileDecryptError>
    where
        RopsTree<Encrypted<C>>: TryFrom<RopsFileMap<Encrypted<C>, F>, Error = MapToTreeError>,
    {
        let _tree = RopsTree::<Encrypted<C>>::try_from(self.map)?;
        todo!()
    }
}
