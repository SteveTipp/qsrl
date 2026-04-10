use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use qsrl::archive::Archive;
use qsrl::commands::{SettingsOverrides, keygen, pack_archive, sign_archive, verify_archive};
use qsrl::error::QsrlError;
use qsrl::protocol::{SignatureAlgorithm, SignaturePlacement};

fn fresh_temp_dir(label: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("qsrl-test-{label}-{}", qsrl::util::unique_id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_sample_input(root: &Path) -> PathBuf {
    let input = root.join("input");
    fs::create_dir_all(input.join("nested")).expect("create nested input");
    fs::write(input.join("a.txt"), b"alpha").expect("write a.txt");
    fs::write(input.join("nested").join("b.txt"), b"beta beta beta").expect("write b.txt");
    input
}

#[test]
fn manifest_generation_is_deterministic() {
    let root = fresh_temp_dir("deterministic");
    let input = write_sample_input(&root);
    let archive_a = root.join("a.qsrl");
    let archive_b = root.join("b.qsrl");

    pack_archive(&root, &input, &archive_a, SettingsOverrides::default()).expect("pack archive a");
    pack_archive(&root, &input, &archive_b, SettingsOverrides::default()).expect("pack archive b");

    let parsed_a = Archive::read_from_path(&archive_a).expect("read archive a");
    let parsed_b = Archive::read_from_path(&archive_b).expect("read archive b");

    assert_eq!(parsed_a.manifest_bytes, parsed_b.manifest_bytes);
    assert_eq!(parsed_a.block_table_bytes, parsed_b.block_table_bytes);
    assert_eq!(parsed_a.payload, parsed_b.payload);
}

#[test]
fn sign_and_verify_round_trip() {
    let root = fresh_temp_dir("round-trip");
    let input = write_sample_input(&root);
    let archive = root.join("sample.qsrl");

    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate key");
    let private_key = root.join("keys").join("ml-dsa-001.private");
    let public_key = root.join("keys").join("ml-dsa-001.public");

    pack_archive(
        &root,
        &input,
        &archive,
        SettingsOverrides {
            signature_algorithm: Some(SignatureAlgorithm::MlDsa),
            ..SettingsOverrides::default()
        },
    )
    .expect("pack archive");
    sign_archive(
        &archive,
        &private_key,
        Some(SignaturePlacement::Embedded),
        None,
    )
    .expect("sign archive");
    let result = verify_archive(&archive, &public_key, None).expect("verify archive");
    assert!(result.contains("signature: ok"));
    assert!(result.contains("file hashes: ok"));
}

#[test]
fn pack_sign_verify_round_trip_for_slh_dsa() {
    let root = fresh_temp_dir("slh-dsa-round-trip");
    let input = write_sample_input(&root);
    let archive = root.join("sample-slh-dsa.qsrl");

    keygen(&root, SignatureAlgorithm::SlhDsa).expect("generate SLH-DSA key");
    let private_key = root.join("keys").join("slh-dsa-001.private");
    let public_key = root.join("keys").join("slh-dsa-001.public");

    pack_archive(
        &root,
        &input,
        &archive,
        SettingsOverrides {
            signature_algorithm: Some(SignatureAlgorithm::SlhDsa),
            ..SettingsOverrides::default()
        },
    )
    .expect("pack archive");
    sign_archive(
        &archive,
        &private_key,
        Some(SignaturePlacement::Embedded),
        None,
    )
    .expect("sign archive");
    let result = verify_archive(&archive, &public_key, None).expect("verify archive");
    assert!(result.contains("signature: ok"));
    assert!(result.contains("algorithm: slh-dsa"));
}

#[test]
fn corrupted_file_data_is_detected() {
    let root = fresh_temp_dir("corruption");
    let input = write_sample_input(&root);
    let archive_path = root.join("corrupt.qsrl");

    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate key");
    let private_key = root.join("keys").join("ml-dsa-001.private");
    let public_key = root.join("keys").join("ml-dsa-001.public");

    pack_archive(&root, &input, &archive_path, SettingsOverrides::default()).expect("pack archive");
    sign_archive(
        &archive_path,
        &private_key,
        Some(SignaturePlacement::Embedded),
        None,
    )
    .expect("sign archive");

    let archive = Archive::read_from_path(&archive_path).expect("read archive");
    let mut bytes = fs::read(&archive_path).expect("read archive bytes");
    let payload_offset = archive.payload_offset();
    bytes[payload_offset] ^= 0x01;
    fs::write(&archive_path, bytes).expect("rewrite archive");

    let error = verify_archive(&archive_path, &public_key, None).expect_err("verify should fail");
    assert!(matches!(error, QsrlError::DataCorruption(_)));
}

#[test]
fn wrong_public_key_is_rejected() {
    let root = fresh_temp_dir("wrong-key");
    let input = write_sample_input(&root);
    let archive = root.join("wrong-key.qsrl");

    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate first key");
    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate second key");
    let private_key = root.join("keys").join("ml-dsa-001.private");
    let wrong_public_key = root.join("keys").join("ml-dsa-002.public");

    pack_archive(&root, &input, &archive, SettingsOverrides::default()).expect("pack archive");
    sign_archive(
        &archive,
        &private_key,
        Some(SignaturePlacement::Embedded),
        None,
    )
    .expect("sign archive");

    let error = verify_archive(&archive, &wrong_public_key, None).expect_err("verify should fail");
    assert!(matches!(error, QsrlError::SignatureVerificationFailed(_)));
}

#[test]
fn unsupported_version_is_rejected() {
    let root = fresh_temp_dir("version");
    let input = write_sample_input(&root);
    let archive_path = root.join("unsupported.qsrl");

    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate key");
    let private_key = root.join("keys").join("ml-dsa-001.private");
    let public_key = root.join("keys").join("ml-dsa-001.public");

    pack_archive(&root, &input, &archive_path, SettingsOverrides::default()).expect("pack archive");
    sign_archive(
        &archive_path,
        &private_key,
        Some(SignaturePlacement::Embedded),
        None,
    )
    .expect("sign archive");

    let mut bytes = fs::read(&archive_path).expect("read archive bytes");
    bytes[6] = 99;
    bytes[7] = 0;
    fs::write(&archive_path, bytes).expect("rewrite archive");

    let error = verify_archive(&archive_path, &public_key, None).expect_err("verify should fail");
    assert!(matches!(error, QsrlError::UnsupportedVersion(99)));
}
