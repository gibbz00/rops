#[cfg(any(feature = "age", feature = "aws-kms"))]
use crate::*;

/// Private keys passed in by the caller, so that decrypting the data key never reads the
/// process-global `ROPS_<INTEGRATION>` environment variables or the default key files.
/// Encrypting it for AWS KMS key ids, as `add_keys` and `remove_integration_key` do, still does.
#[derive(Default)]
pub struct ExplicitPrivateKeys {
    #[cfg(feature = "age")]
    pub age: Vec<<AgeIntegration as Integration>::PrivateKey>,
    #[cfg(feature = "aws-kms")]
    pub aws_kms: Vec<<AwsKmsIntegration as Integration>::PrivateKey>,
}

impl ExplicitPrivateKeys {
    /// Accepts both the comma separated `ROPS_AGE` format and the one key per line key file format.
    #[cfg(feature = "age")]
    pub fn age_from_str(private_keys_str: &str) -> IntegrationResult<Self> {
        Ok(Self {
            age: parse_private_keys::<AgeIntegration>(private_keys_str)?,
            #[cfg(feature = "aws-kms")]
            aws_kms: Vec::new(),
        })
    }

    /// Accepts both the comma separated `ROPS_AWS_KMS` format and the one key per line key file format.
    #[cfg(feature = "aws-kms")]
    pub fn aws_kms_from_str(private_keys_str: &str) -> IntegrationResult<Self> {
        Ok(Self {
            aws_kms: parse_private_keys::<AwsKmsIntegration>(private_keys_str)?,
            #[cfg(feature = "age")]
            age: Vec::new(),
        })
    }
}

#[cfg(any(feature = "age", feature = "aws-kms"))]
fn parse_private_keys<I: Integration>(private_keys_str: &str) -> IntegrationResult<Vec<I::PrivateKey>> {
    private_keys_str
        .split([',', '\n'])
        .map(str::trim)
        .filter(|private_key_str| !private_key_str.is_empty())
        .map(I::parse_private_key)
        .collect()
}

#[cfg(all(test, feature = "age"))]
mod tests {
    use super::*;

    #[test]
    fn parses_age_private_keys() {
        let mock_private_key_str = AgeIntegration::mock_private_key_str();
        let mock_private_key_str = mock_private_key_str.as_ref();
        let private_keys_str = format!("{mock_private_key_str},\n {mock_private_key_str}\n\n");

        let explicit_private_keys = ExplicitPrivateKeys::age_from_str(&private_keys_str).unwrap();

        assert_eq!(2, explicit_private_keys.age.len());
        assert!(explicit_private_keys
            .age
            .iter()
            .all(|private_key| private_key.to_public() == AgeIntegration::mock_private_key().to_public()));
    }

    #[test]
    fn rejects_invalid_age_private_key() {
        assert!(matches!(
            ExplicitPrivateKeys::age_from_str("invalid"),
            Err(IntegrationError::PrivateKeyParsing(_))
        ));
    }
}
