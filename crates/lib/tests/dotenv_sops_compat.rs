#![cfg(all(feature = "age", feature = "dotenv", feature = "aes-gcm", feature = "sha2", feature = "test-utils"))]

use rops::{
    cryptography::{cipher::AES256GCM, hasher::SHA512},
    file::{builder::RopsFileBuilder, format::DotenvFileFormat, state::*, RopsFile},
    integration::*,
};

const MOCK_RECIPIENT: &str = "age1se5ghfycr4n8kcwc3qwf234ymvmr2lex2a99wh8gpfx97glwt9hqch4569";

const SOPS_ENCRYPTED: &str = include_str!("sops_references/age_dotenv_example.env");
const SOPS_PLAINTEXT: &str = include_str!("sops_references/age_dotenv_example_plaintext.env");
const ROPS_ENCRYPTED: &str = include_str!("sops_references/age_dotenv_rops_encrypted.env");

/// sops output must decrypt in rops and re-encrypt byte for byte with the saved parameters.
#[test]
fn sops_dotenv_decrypts_and_reencrypts_identically() {
    AgeIntegration::set_mock_private_key_env_var();

    let (decrypted, saved_parameters) = SOPS_ENCRYPTED
        .parse::<RopsFile<EncryptedFile<AES256GCM, SHA512>, DotenvFileFormat>>()
        .unwrap()
        .decrypt_and_save_parameters::<DotenvFileFormat>()
        .unwrap();

    pretty_assertions::assert_eq!(SOPS_PLAINTEXT, decrypted.map().to_string());
    pretty_assertions::assert_eq!(
        SOPS_ENCRYPTED,
        decrypted
            .encrypt_with_saved_parameters::<AES256GCM, DotenvFileFormat>(saved_parameters)
            .unwrap()
            .to_string()
    );
}

/// A file encrypted by rops (fixture checked with the sops binary) decrypts in rops.
#[test]
fn rops_dotenv_fixture_decrypts() {
    AgeIntegration::set_mock_private_key_env_var();

    let (decrypted, _) = ROPS_ENCRYPTED
        .parse::<RopsFile<EncryptedFile<AES256GCM, SHA512>, DotenvFileFormat>>()
        .unwrap()
        .decrypt_and_save_parameters::<DotenvFileFormat>()
        .unwrap();

    pretty_assertions::assert_eq!(SOPS_PLAINTEXT, decrypted.map().to_string());
}

/// Regenerates `sops_references/age_dotenv_rops_encrypted.env`. Run with `--ignored`, then check
/// the output with the sops binary.
#[test]
#[ignore = "regenerates the rops-encrypted dotenv fixture"]
fn write_rops_dotenv_fixture() {
    let recipient: age::x25519::Recipient = MOCK_RECIPIENT.parse().unwrap();
    let file = RopsFileBuilder::<DotenvFileFormat>::new(SOPS_PLAINTEXT)
        .unwrap()
        .add_integration_key::<AgeIntegration>(recipient)
        .encrypt::<AES256GCM, SHA512>()
        .unwrap();
    std::fs::write(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/sops_references/age_dotenv_rops_encrypted.env"),
        file.to_string(),
    )
    .unwrap();
}
