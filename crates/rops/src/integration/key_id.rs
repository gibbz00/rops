use crate::*;

pub trait IntegrationKeyId<I: Integration> {
    fn append_to_builder<F: FileFormat>(self, rops_file_builder: &mut RopsFileBuilder<F>);
}
