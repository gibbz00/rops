// GOAL: serialize age into
// ENC[AES256_GCM,data:EjRPNlhx,iv:XmS4b2ZqB39Qjpl/IQRm36KLclV8wXuBjuZsw4yekcU=,tag:
// SWK3XZBBUA49muEyeqld4g==,type:str]

use std::fmt::{Display, Formatter};

use crate::*;

#[derive(Debug, PartialEq)]
pub struct EncryptedValue {
    data: EncryptedValueData,
    metadata: EncryptedValueMetaData,
}

impl Display for EncryptedValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ENC[{},data:{},iv:{},tag:{},type:{}]",
            self.metadata.cipher_variant.as_ref(),
            self.data.except_tag(self.metadata.cipher_variant.cipher()).encode_base64(),
            self.metadata.initial_value.encode_base64(),
            self.data.tag(self.metadata.cipher_variant.cipher()).encode_base64(),
            self.metadata.value_type.as_ref(),
        )
    }
}

#[cfg(feature = "test-utils")]
mod mock {
    use super::*;

    impl MockTestUtil for EncryptedValue {
        fn mock() -> Self {
            Self {
                data: MockTestUtil::mock(),
                metadata: MockTestUtil::mock(),
            }
        }
    }

    impl MockStringTestUtil for EncryptedValue {
        fn mock_string() -> String {
            format!(
                "ENC[AES256_GCM,data:{},iv:kwtVOk4u/wLHMovHYG2ngLv+uM8U9UJrIxjS6zCKmVY=,tag:{},type:str]",
                EncryptedValueDataExceptTag::mock_string(),
                EncryptedValueDataAuthorizationTag::mock_string()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_value_encryption_content() {
        DisplayTestUtils::assert_display::<EncryptedValue>()
    }

    #[test]
    fn parses_value_encryption_content() {}
}
