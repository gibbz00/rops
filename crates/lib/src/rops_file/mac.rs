use std::ops::Add;

use generic_array::{typenum::Sum, ArrayLength, GenericArray};

use crate::*;

const MAC_ENCRYPTED_ONLY_INIT_BYTES: [u8; 32] = [
    0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52, 0x7b, 0x10, 0x34, 0xf3, 0xd1, 0x47, 0xbe, 0xb, 0xb, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72,
    0xc6, 0xfd, 0xad, 0xec, 0x81, 0x76, 0xf2, 0x7d, 0x69,
];

#[derive(Debug)]
pub struct Mac<H: Hasher>(GenericArray<u8, Sum<H::OutputSize, H::OutputSize>>)
where
    H::OutputSize: Add<H::OutputSize>,
    Sum<H::OutputSize, H::OutputSize>: ArrayLength<u8>;

impl<H: Hasher> Mac<H>
where
    H::OutputSize: Add<H::OutputSize>,
    Sum<H::OutputSize, H::OutputSize>: ArrayLength<u8>,
{
    pub fn compute(from_encrypted_values_only: bool, decrypted_map: &RopsMap<Decrypted>) -> Self {
        let mut hasher = H::new();
        if from_encrypted_values_only {
            hasher.update(MAC_ENCRYPTED_ONLY_INIT_BYTES);
        }

        traverse_map(&mut hasher, from_encrypted_values_only, decrypted_map);

        // IMPROVEMENT: would be nice if the heap allocation could be avoided.
        return Mac(GenericArray::from_iter(format!("{:X}", hasher.finalize()).into_bytes()));

        fn traverse_map<Ha: Hasher>(hasher: &mut Ha, hash_encrypted_values_only: bool, map: &RopsMap<Decrypted>) {
            traverse_map_recursive(hasher, hash_encrypted_values_only, map);

            fn traverse_map_recursive<H: Hasher>(hasher: &mut H, hash_encrypted_values_only: bool, map: &RopsMap<Decrypted>) {
                for (_, tree) in map.iter() {
                    traverse_tree_recursive(hasher, hash_encrypted_values_only, tree)
                }
            }

            fn traverse_tree_recursive<H: Hasher>(hasher: &mut H, hash_encrypted_values_only: bool, tree: &RopsTree<Decrypted>) {
                match tree {
                    RopsTree::Sequence(sequence) => sequence
                        .iter()
                        .for_each(|sub_tree| traverse_tree_recursive(hasher, hash_encrypted_values_only, sub_tree)),
                    RopsTree::Map(map) => traverse_map_recursive(hasher, hash_encrypted_values_only, map),
                    RopsTree::Null => (),
                    RopsTree::Leaf(value) => {
                        // TODO: use hash_encrypted_only once partial encryption is added
                        hasher.update(value.as_bytes())
                    }
                }
            }
        }
    }

    pub fn encrypt<C: Cipher>(
        self,
        data_key: &DataKey,
        last_modified_date_time: &LastModifiedDateTime,
    ) -> Result<EncryptedRopsValue<C>, C::Error> {
        let mut in_place_buffer = self.0;
        let nonce = Nonce::new();
        let authorization_tag = C::encrypt(
            &nonce,
            data_key,
            in_place_buffer.as_mut_slice(),
            last_modified_date_time.as_ref().to_rfc3339().as_bytes(),
        )?;

        Ok(EncryptedRopsValue {
            data: in_place_buffer.to_vec().into(),
            authorization_tag,
            nonce,
            value_variant: RopsValueVariant::String,
        })
    }

    pub fn decrypt<C: Cipher>(
        encrypted_value: EncryptedRopsValue<C>,
        data_key: &DataKey,
        last_modified_date_time: &LastModifiedDateTime,
    ) -> Result<Self, C::Error> {
        let mut in_place_buffer = GenericArray::<_, _>::from_iter(Vec::from(encrypted_value.data));
        C::decrypt(
            &encrypted_value.nonce,
            data_key,
            in_place_buffer.as_mut(),
            last_modified_date_time.as_ref().to_rfc3339().as_bytes(),
            &encrypted_value.authorization_tag,
        )?;

        Ok(Self(in_place_buffer))
    }
}

// WORKAROUND: derive proc macro struggles with trait bounds
impl<H: Hasher> PartialEq for Mac<H>
where
    H::OutputSize: Add<H::OutputSize>,
    Sum<H::OutputSize, H::OutputSize>: ArrayLength<u8>,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    #[cfg(feature = "sha2")]
    mod sha2 {
        use super::*;

        impl<H: Hasher> MockTestUtil for Mac<H>
        where
            H::OutputSize: Add<H::OutputSize>,
            Sum<H::OutputSize, H::OutputSize>: ArrayLength<u8>,
        {
            fn mock() -> Self {
                Self(GenericArray::from_slice(b"A0FBBFF515AC1EF88827C911653675DE4155901880355C59BA4FE4043395A0DE5EA77762EB3CAC54CC6F2B37EDDD916127A32566E810B0A5DADFA2F60B061331").to_owned())
            }
        }

        #[cfg(feature = "aes-gcm")]
        mod aes_gcm {
            use super::*;

            impl MockDisplayTestUtil for Mac<SHA512> {
                fn mock_display() -> String {
                    "ENC[AES256_GCM,data:W1CX5S5kbJ6f4uKuo6G5083Ekp50RAzqheQjbMEJpF1eZ7+d1/KSrLWIWjqZlyvzTDB1aMWp8xcOmCRCKyGn2cZCrr8SXU1yxpWW/42xue48LjFB0PVPt7YNTUtKrkb7KXOuvIrZ5HOXgoGpahopVCh06mG/T3hEHm/i2z/pzwk=,iv:fSPQ/8OhW8Mw2GMBHsO+qnhN4aKIN2sJYMNfjuxM+A8=,tag:kzpxGxIx4bVstvZrtMSFGQ==,type:str]".to_string()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "sha2")]
    mod sha2 {
        use crate::*;

        #[test]
        fn computes_mac() {
            assert_eq!(Mac::mock(), Mac::<SHA512>::compute(false, &RopsMap::mock()))
        }

        #[cfg(feature = "aes-gcm")]
        mod aes_gcm {
            use super::*;

            #[test]
            fn decrypts_mac() {
                assert_eq!(
                    Mac::<SHA512>::mock(),
                    Mac::decrypt::<AES256GCM>(
                        Mac::mock_display().parse().unwrap(),
                        &DataKey::mock(),
                        &LastModifiedDateTime::mock()
                    )
                    .unwrap()
                )
            }

            #[test]
            fn encrypts_mac() {
                let data_key = DataKey::mock();
                let last_modified = LastModifiedDateTime::mock();

                let encrypted = Mac::<SHA512>::mock().encrypt::<AES256GCM>(&data_key, &last_modified).unwrap();
                let decrypted = Mac::<SHA512>::decrypt(encrypted, &data_key, &last_modified).unwrap();

                assert_eq!(Mac::mock(), decrypted)
            }
        }
    }
}
