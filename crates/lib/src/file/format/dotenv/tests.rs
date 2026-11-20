use serde_json::{json, Value};

use crate::*;

const SOPS_SHAPED: &str = "A=hello\n\
B=two words\n\
C=x#y\n\
sops_age__list_0__map_recipient=age1xyz\n\
sops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\\nYWdl\\n-----END AGE ENCRYPTED FILE-----\n\
sops_lastmodified=2026-11-20T03:46:26Z\n\
sops_unencrypted_suffix=_unencrypted\n\
sops_version=3.13.3\n\
sops_mac=ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\n";

#[test]
fn parses_plain_keys_and_sops_metadata() {
    let value: Value = DotenvFileFormat::deserialize_from_str(SOPS_SHAPED).unwrap();
    assert_eq!(value["A"], "hello");
    assert_eq!(value["B"], "two words");
    assert_eq!(value["C"], "x#y");
    assert_eq!(value["sops"]["age"][0]["recipient"], "age1xyz");
    assert_eq!(
        value["sops"]["age"][0]["enc"],
        "-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----"
    );
    assert_eq!(value["sops"]["version"], "3.13.3");
    assert_eq!(value["sops"]["unencrypted_suffix"], "_unencrypted");
    assert_eq!(value["sops"]["mac"], "ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]");
}

#[test]
fn round_trip_keeps_document() {
    let first: Value = DotenvFileFormat::deserialize_from_str(SOPS_SHAPED).unwrap();
    let text = DotenvFileFormat::serialize_to_string(&first).unwrap();
    let second: Value = DotenvFileFormat::deserialize_from_str(&text).unwrap();
    assert_eq!(first, second);
}

#[test]
fn serializes_sops_style_metadata_names() {
    let doc = json!({
        "A": "hello",
        "sops": {"age": [{"recipient": "age1xyz", "enc": "line1\nline2"}], "version": "3.13.3"}
    });
    let text = DotenvFileFormat::serialize_to_string(&doc).unwrap();
    assert!(text.contains("A=hello\n"));
    assert!(text.contains("sops_age__list_0__map_recipient=age1xyz\n"));
    assert!(text.contains("sops_age__list_0__map_enc=line1\\nline2\n"));
    assert!(text.contains("sops_version=3.13.3\n"));
}

#[test]
fn rejects_newline_in_plain_value() {
    let doc = json!({"A": "x\ny"});
    assert!(DotenvFileFormat::serialize_to_string(&doc).is_err());
}

#[test]
fn writes_scalars_as_text() {
    let doc = json!({"N": 3, "B": true, "S": "x"});
    let text = DotenvFileFormat::serialize_to_string(&doc).unwrap();
    assert!(text.contains("N=3\n"));
    assert!(text.contains("B=true\n"));
    assert!(text.contains("S=x\n"));
}

#[test]
fn rejects_complex_plain_value_like_sops() {
    for doc in [json!({"L": ["a"]}), json!({"M": {"k": "v"}})] {
        let error = DotenvFileFormat::serialize_to_string(&doc).unwrap_err();
        assert!(error
            .to_string()
            .starts_with("cannot use complex value in dotenv file; offending key"));
    }
}

#[test]
fn rejects_line_without_equals() {
    let result: Result<Value, _> = DotenvFileFormat::deserialize_from_str("NOEQUALS\n");
    assert!(result.is_err());
}

impl FileFormatTestSuiteUtils for DotenvFileFormat {
    fn simple_map(key: impl std::fmt::Display, value: impl std::fmt::Display) -> String {
        format!("{key}={value}\n")
    }
}

#[cfg(all(feature = "aes-gcm", feature = "sha2", feature = "age"))]
mod rops_file {
    use super::*;

    #[test]
    fn serializes_decrypted_rops_file() {
        FileFormatTestUtils::assert_serialization::<DotenvFileFormat, RopsFile<DecryptedFile<SHA512>, DotenvFileFormat>>()
    }

    #[test]
    fn deserializes_decrypted_rops_file() {
        FileFormatTestUtils::assert_deserialization::<DotenvFileFormat, RopsFile<DecryptedFile<SHA512>, DotenvFileFormat>>()
    }

    #[test]
    fn serializes_encrypted_rops_file() {
        FileFormatTestUtils::assert_serialization::<DotenvFileFormat, RopsFile<EncryptedFile<AES256GCM, SHA512>, DotenvFileFormat>>()
    }

    #[test]
    fn deserializes_encrypted_rops_file() {
        FileFormatTestUtils::assert_deserialization::<DotenvFileFormat, RopsFile<EncryptedFile<AES256GCM, SHA512>, DotenvFileFormat>>()
    }
}

#[cfg(feature = "aes-gcm")]
mod adapters {
    use super::*;

    #[test]
    fn decrypted_map_round_trips_through_internal() {
        let internal = RopsFileFormatMap::<DecryptedMap, DotenvFileFormat>::mock().to_internal().unwrap();
        let external: RopsFileFormatMap<DecryptedMap, DotenvFileFormat> = internal.to_external();
        pretty_assertions::assert_eq!(RopsFileFormatMap::<DecryptedMap, DotenvFileFormat>::mock(), external)
    }

    #[test]
    fn encrypted_map_round_trips_through_internal() {
        let internal = RopsFileFormatMap::<EncryptedMap<AES256GCM>, DotenvFileFormat>::mock()
            .to_internal(MockTestUtil::mock())
            .unwrap();
        let external: RopsFileFormatMap<EncryptedMap<AES256GCM>, DotenvFileFormat> = internal.to_external();
        pretty_assertions::assert_eq!(RopsFileFormatMap::<EncryptedMap<AES256GCM>, DotenvFileFormat>::mock(), external)
    }

    #[test]
    fn disallows_plaintext_string_when_encrypted() {
        let map = DotenvFileFormat::key_value_map::<EncryptedMap<StubCipher>>("plain", "value");
        assert!(matches!(
            map.to_internal(None).unwrap_err(),
            FormatToInternalMapError::EncryptedRopsValue(_)
        ))
    }
}
