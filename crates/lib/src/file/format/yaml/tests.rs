use std::fmt::Display;

use crate::*;

impl FileFormatTestSuiteUtils for YamlFileFormat {
    fn simple_map(key: impl Display, value: impl Display) -> String {
        format!("{key}: {value}")
    }
}

generate_file_format_test_suite!(YamlFileFormat);

#[test]
fn encrypted_disallows_non_string_keys() {
    assert!(matches!(
        YamlFileFormat::key_value_map::<EncryptedMap<StubCipher>>(123, "xxx")
            .to_internal(None)
            .unwrap_err(),
        FormatToInternalMapError::NonStringKey(_)
    ))
}

#[test]
fn decrypted_disallows_non_string_keys() {
    assert!(matches!(
        YamlFileFormat::key_value_map::<DecryptedMap>(123, "xxx").to_internal().unwrap_err(),
        FormatToInternalMapError::NonStringKey(_)
    ))
}
