use derive_more::{Deref, DerefMut};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Deref, DerefMut)]
#[impl_tools::autoimpl(Default, Debug, PartialEq)]
pub struct IntegrationMetadataUnits<I: Integration>(IndexMap<I::KeyId, IntegrationMetadataUnit<I>>);

impl<I: Integration> IntegrationMetadataUnits<I> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Overrides any pre-existing integration metadata unit.
    pub fn insert(&mut self, unit: IntegrationMetadataUnit<I>)
    where
        I::KeyId: Clone,
    {
        self.0.insert(unit.config.key_id().clone(), unit);
    }
}

impl<I: Integration> Serialize for IntegrationMetadataUnits<I>
where
    I::Config: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.0.values())
    }
}

impl<'de, I: Integration> Deserialize<'de> for IntegrationMetadataUnits<I>
where
    I::KeyId: Clone,
    IntegrationMetadataUnit<I>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Vec::<IntegrationMetadataUnit<I>>::deserialize(deserializer).map(|units_collection| {
            units_collection.into_iter().fold(Self::default(), |mut units, unit| {
                units.insert(unit);
                units
            })
        })
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use indexmap::indexmap;

    use super::*;

    impl<I: Integration> MockTestUtil for IntegrationMetadataUnits<I>
    where
        I::KeyId: MockTestUtil,
        IntegrationMetadataUnit<I>: MockTestUtil,
    {
        fn mock() -> Self {
            Self(indexmap! {I::KeyId::mock() => IntegrationMetadataUnit::mock()})
        }
    }
}
