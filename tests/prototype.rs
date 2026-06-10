use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use qsrl::archive::Archive;
use qsrl::commands::{
    SettingsOverrides, extract_archive, keygen, pack_archive, sign_archive, verify_archive,
};
#[cfg(feature = "liboqs-backend")]
use qsrl::commands::{
    extract_archive_with_recipient, inspect_archive, pack_archive_with_recipients, recipient_keygen,
};
use qsrl::error::QsrlError;
#[cfg(feature = "liboqs-backend")]
use qsrl::protocol::KemAlgorithm;
use qsrl::protocol::{CompressionLayout, CompressionMode, SignatureAlgorithm, SignaturePlacement};

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

fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn visit(root: &Path, current: &Path, output: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(current).expect("read tree entry") {
            let entry = entry.expect("read dir entry");
            let path = entry.path();
            if path.is_dir() {
                visit(root, &path, output);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("path inside root")
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(relative, fs::read(&path).expect("read file"));
            }
        }
    }

    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
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

#[cfg(unix)]
#[test]
fn generated_private_key_file_is_mode_0600() {
    use std::os::unix::fs::PermissionsExt;

    let root = fresh_temp_dir("key-permissions");
    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate key");
    let private_key = root.join("keys").join("ml-dsa-001.private");

    let mode = fs::metadata(&private_key)
        .expect("private key metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn extract_round_trip_from_signed_archive() {
    let root = fresh_temp_dir("extract-round-trip");
    let input = write_sample_input(&root);
    let archive = root.join("extract.qsrl");
    let output = root.join("extracted");

    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate key");
    let private_key = root.join("keys").join("ml-dsa-001.private");
    let public_key = root.join("keys").join("ml-dsa-001.public");

    pack_archive(&root, &input, &archive, SettingsOverrides::default()).expect("pack archive");
    sign_archive(
        &archive,
        &private_key,
        Some(SignaturePlacement::Embedded),
        None,
    )
    .expect("sign archive");

    let result =
        extract_archive(&archive, &output, Some(&public_key), None).expect("extract archive");
    assert!(result.contains("signature: ok"));
    assert_eq!(read_tree(&input), read_tree(&output));
}

#[test]
fn extract_round_trip_with_detached_signature() {
    let root = fresh_temp_dir("extract-detached");
    let input = write_sample_input(&root);
    let archive = root.join("extract-detached.qsrl");
    let output = root.join("extracted-detached");
    let detached_signature = root.join("extract-detached.sig");

    keygen(&root, SignatureAlgorithm::SlhDsa).expect("generate key");
    let private_key = root.join("keys").join("slh-dsa-001.private");
    let public_key = root.join("keys").join("slh-dsa-001.public");

    pack_archive(
        &root,
        &input,
        &archive,
        SettingsOverrides {
            signature_algorithm: Some(SignatureAlgorithm::SlhDsa),
            signature_placement: Some(SignaturePlacement::Detached),
            ..SettingsOverrides::default()
        },
    )
    .expect("pack archive");
    sign_archive(
        &archive,
        &private_key,
        Some(SignaturePlacement::Detached),
        Some(&detached_signature),
    )
    .expect("sign archive");

    let result = extract_archive(
        &archive,
        &output,
        Some(&public_key),
        Some(&detached_signature),
    )
    .expect("extract archive");
    assert!(result.contains("signature: ok"));
    assert_eq!(read_tree(&input), read_tree(&output));
}

#[test]
fn extract_round_trip_for_per_file_rle_layout() {
    let root = fresh_temp_dir("extract-rle-per-file");
    let input = write_sample_input(&root);
    let archive = root.join("extract-per-file.qsrl");
    let output = root.join("extracted-per-file");

    pack_archive(
        &root,
        &input,
        &archive,
        SettingsOverrides {
            compression_mode: Some(CompressionMode::Rle),
            compression_layout: Some(CompressionLayout::PerFile),
            ..SettingsOverrides::default()
        },
    )
    .expect("pack archive");

    extract_archive(&archive, &output, None, None).expect("extract archive");
    assert_eq!(read_tree(&input), read_tree(&output));
}

#[test]
fn extract_round_trip_for_whole_archive_rle_layout() {
    let root = fresh_temp_dir("extract-rle-whole");
    let input = write_sample_input(&root);
    let archive = root.join("extract-whole.qsrl");
    let output = root.join("extracted-whole");

    pack_archive(
        &root,
        &input,
        &archive,
        SettingsOverrides {
            compression_mode: Some(CompressionMode::Rle),
            compression_layout: Some(CompressionLayout::WholeArchive),
            ..SettingsOverrides::default()
        },
    )
    .expect("pack archive");

    extract_archive(&archive, &output, None, None).expect("extract archive");
    assert_eq!(read_tree(&input), read_tree(&output));
}

#[test]
fn extract_rejects_path_traversal() {
    let root = fresh_temp_dir("extract-traversal");
    let input = write_sample_input(&root);
    let archive_path = root.join("traversal.qsrl");
    let output = root.join("extracted");

    pack_archive(&root, &input, &archive_path, SettingsOverrides::default()).expect("pack archive");

    let mut archive = Archive::read_from_path(&archive_path).expect("read archive");
    archive.manifest.files[0].path = "../escape.txt".into();
    archive.manifest_bytes = archive.manifest.serialize().expect("serialize manifest");
    archive
        .write_to_path(&archive_path)
        .expect("rewrite archive");

    let error =
        extract_archive(&archive_path, &output, None, None).expect_err("extract should fail");
    assert!(matches!(error, QsrlError::InvalidFormat(_)));
    assert!(!output.exists());
    assert!(!root.join("escape.txt").exists());
}

#[cfg(unix)]
#[test]
fn extract_rejects_existing_symlink_component() {
    let root = fresh_temp_dir("extract-symlink");
    let input = write_sample_input(&root);
    let archive_path = root.join("symlink.qsrl");
    let output = root.join("extracted");
    let outside = root.join("outside");

    pack_archive(&root, &input, &archive_path, SettingsOverrides::default()).expect("pack archive");
    fs::create_dir_all(&output).expect("create output");
    fs::create_dir_all(&outside).expect("create outside");
    std::os::unix::fs::symlink(&outside, output.join("nested")).expect("create symlink");

    let error =
        extract_archive(&archive_path, &output, None, None).expect_err("extract should fail");
    assert!(matches!(error, QsrlError::InvalidFormat(_)));
    assert!(!outside.join("b.txt").exists());
}

#[test]
fn extract_refuses_to_overwrite_existing_file() {
    let root = fresh_temp_dir("extract-overwrite");
    let input = write_sample_input(&root);
    let archive_path = root.join("overwrite.qsrl");
    let output = root.join("extracted");

    pack_archive(&root, &input, &archive_path, SettingsOverrides::default()).expect("pack archive");
    fs::create_dir_all(&output).expect("create output");
    fs::write(output.join("a.txt"), b"keep me").expect("write existing file");

    let error =
        extract_archive(&archive_path, &output, None, None).expect_err("extract should fail");
    assert!(matches!(error, QsrlError::Usage(_)));
    assert_eq!(
        fs::read(output.join("a.txt")).expect("read existing file"),
        b"keep me"
    );
}

#[test]
fn extract_rejects_corruption_before_writing() {
    let root = fresh_temp_dir("extract-corruption");
    let input = write_sample_input(&root);
    let archive_path = root.join("corrupt-extract.qsrl");
    let output = root.join("extracted");

    pack_archive(&root, &input, &archive_path, SettingsOverrides::default()).expect("pack archive");

    let archive = Archive::read_from_path(&archive_path).expect("read archive");
    let mut bytes = fs::read(&archive_path).expect("read archive bytes");
    let payload_offset = archive.payload_offset();
    bytes[payload_offset] ^= 0x01;
    fs::write(&archive_path, bytes).expect("rewrite archive");

    let error =
        extract_archive(&archive_path, &output, None, None).expect_err("extract should fail");
    assert!(matches!(error, QsrlError::DataCorruption(_)));
    assert!(!output.exists());
}

#[test]
fn sparse_text_manifest_index_is_rejected() {
    let root = fresh_temp_dir("sparse-manifest");
    let input = write_sample_input(&root);
    let archive_path = root.join("sparse.qsrl");

    pack_archive(&root, &input, &archive_path, SettingsOverrides::default()).expect("pack archive");
    let mut archive = Archive::read_from_path(&archive_path).expect("read archive");
    let manifest = String::from_utf8(archive.manifest_bytes.clone()).expect("manifest utf8");
    archive.manifest_bytes = manifest
        .replace("file.0.path=", "file.999999.path=")
        .into_bytes();
    archive
        .write_to_path(&archive_path)
        .expect("rewrite archive");

    let error = Archive::read_from_path(&archive_path).expect_err("sparse manifest should fail");
    assert!(matches!(error, QsrlError::InvalidFormat(_)));
}

#[test]
fn huge_block_table_count_is_rejected_before_allocation() {
    let root = fresh_temp_dir("huge-block-count");
    let input = write_sample_input(&root);
    let archive_path = root.join("huge-block-count.qsrl");

    pack_archive(&root, &input, &archive_path, SettingsOverrides::default()).expect("pack archive");
    let mut archive = Archive::read_from_path(&archive_path).expect("read archive");
    archive.block_table_bytes[6..10].copy_from_slice(&u32::MAX.to_le_bytes());
    archive
        .write_to_path(&archive_path)
        .expect("rewrite archive");

    let error = Archive::read_from_path(&archive_path).expect_err("huge block count should fail");
    assert!(matches!(error, QsrlError::InvalidFormat(_)));
}

#[test]
fn trailing_archive_bytes_are_rejected() {
    let root = fresh_temp_dir("trailing-bytes");
    let input = write_sample_input(&root);
    let archive_path = root.join("trailing.qsrl");

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
    bytes.extend_from_slice(b"trailing junk");
    fs::write(&archive_path, bytes).expect("rewrite archive");

    let error = verify_archive(&archive_path, &public_key, None).expect_err("verify should fail");
    assert!(matches!(error, QsrlError::InvalidFormat(_)));
}

#[cfg(feature = "liboqs-backend")]
#[test]
fn encrypted_archive_creation_and_decrypt_extract_round_trip() {
    let root = fresh_temp_dir("encrypted-round-trip");
    let input = write_sample_input(&root);
    let archive = root.join("encrypted.qsrl");
    let output = root.join("decrypted");

    recipient_keygen(&root, KemAlgorithm::MlKem).expect("generate recipient key");
    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate signature key");
    let recipient_private_key = root.join("keys").join("ml-kem-001.private");
    let recipient_public_key = root.join("keys").join("ml-kem-001.public");
    let signature_private_key = root.join("keys").join("ml-dsa-001.private");
    let signature_public_key = root.join("keys").join("ml-dsa-001.public");

    pack_archive_with_recipients(
        &root,
        &input,
        &archive,
        SettingsOverrides::default(),
        std::slice::from_ref(&recipient_public_key),
    )
    .expect("pack encrypted archive");
    let parsed = Archive::read_from_path(&archive).expect("read encrypted archive");
    assert!(parsed.encryption.is_some());

    sign_archive(
        &archive,
        &signature_private_key,
        Some(SignaturePlacement::Embedded),
        None,
    )
    .expect("sign archive");
    let verify_output =
        verify_archive(&archive, &signature_public_key, None).expect("verify archive");
    assert!(verify_output.contains("signature: ok"));
    assert!(
        verify_output
            .contains("signature only; encrypted payload not authenticated until decrypt/extract")
    );

    let extract_output = extract_archive_with_recipient(
        &archive,
        &output,
        Some(&signature_public_key),
        None,
        Some(&recipient_private_key),
    )
    .expect("decrypt and extract archive");
    assert!(extract_output.contains("encryption: decrypted"));
    assert!(extract_output.contains("signature: ok"));
    assert_eq!(read_tree(&input), read_tree(&output));
}

#[cfg(feature = "liboqs-backend")]
#[test]
fn encrypted_archive_extract_without_signature_check_round_trip() {
    let root = fresh_temp_dir("encrypted-no-signature-check");
    let input = write_sample_input(&root);
    let archive = root.join("encrypted-no-signature-check.qsrl");
    let output = root.join("decrypted");

    recipient_keygen(&root, KemAlgorithm::MlKem).expect("generate recipient key");
    let recipient_private_key = root.join("keys").join("ml-kem-001.private");
    let recipient_public_key = root.join("keys").join("ml-kem-001.public");

    pack_archive_with_recipients(
        &root,
        &input,
        &archive,
        SettingsOverrides::default(),
        std::slice::from_ref(&recipient_public_key),
    )
    .expect("pack encrypted archive");

    let extract_output =
        extract_archive_with_recipient(&archive, &output, None, None, Some(&recipient_private_key))
            .expect("decrypt and extract archive");
    assert!(extract_output.contains("encryption: decrypted"));
    assert_eq!(read_tree(&input), read_tree(&output));
}

#[cfg(feature = "liboqs-backend")]
#[test]
fn encrypted_archive_detached_signature_extract_round_trip() {
    let root = fresh_temp_dir("encrypted-detached-extract");
    let input = write_sample_input(&root);
    let archive = root.join("encrypted-detached.qsrl");
    let output = root.join("decrypted");
    let detached_signature = root.join("encrypted-detached.sig");

    recipient_keygen(&root, KemAlgorithm::MlKem).expect("generate recipient key");
    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate signature key");
    let recipient_private_key = root.join("keys").join("ml-kem-001.private");
    let recipient_public_key = root.join("keys").join("ml-kem-001.public");
    let signature_private_key = root.join("keys").join("ml-dsa-001.private");
    let signature_public_key = root.join("keys").join("ml-dsa-001.public");

    pack_archive_with_recipients(
        &root,
        &input,
        &archive,
        SettingsOverrides::default(),
        std::slice::from_ref(&recipient_public_key),
    )
    .expect("pack encrypted archive");
    let archive_bytes_before_sign = fs::read(&archive).expect("read encrypted archive bytes");

    let sign_output = sign_archive(
        &archive,
        &signature_private_key,
        Some(SignaturePlacement::Detached),
        Some(&detached_signature),
    )
    .expect("sign encrypted archive with detached signature");
    assert!(sign_output.contains("archive unchanged"));
    assert_eq!(
        archive_bytes_before_sign,
        fs::read(&archive).expect("read signed archive bytes")
    );

    let verify_output = verify_archive(&archive, &signature_public_key, Some(&detached_signature))
        .expect("verify detached signature");
    assert!(verify_output.contains("signature: ok"));
    assert!(verify_output.contains("placement: detached"));

    let inspect_output = inspect_archive(&archive).expect("inspect detached-signed archive");
    assert!(inspect_output.contains("signature placement: none"));
    assert!(inspect_output.contains("signature status: no embedded signature"));
    assert!(!inspect_output.contains("signature placement: embedded"));

    let extract_output = extract_archive_with_recipient(
        &archive,
        &output,
        Some(&signature_public_key),
        Some(&detached_signature),
        Some(&recipient_private_key),
    )
    .expect("decrypt and extract detached-signed archive");
    assert!(extract_output.contains("signature: ok"));
    assert!(extract_output.contains("encryption: decrypted"));
    assert_eq!(read_tree(&input), read_tree(&output));
}

#[cfg(feature = "liboqs-backend")]
#[test]
fn encrypted_archive_detached_signature_rejects_wrong_public_key() {
    let root = fresh_temp_dir("encrypted-detached-wrong-pubkey");
    let input = write_sample_input(&root);
    let archive = root.join("encrypted-detached-wrong-pubkey.qsrl");
    let output = root.join("decrypted");
    let detached_signature = root.join("encrypted-detached-wrong-pubkey.sig");

    recipient_keygen(&root, KemAlgorithm::MlKem).expect("generate recipient key");
    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate first signature key");
    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate second signature key");
    let recipient_private_key = root.join("keys").join("ml-kem-001.private");
    let recipient_public_key = root.join("keys").join("ml-kem-001.public");
    let signature_private_key = root.join("keys").join("ml-dsa-001.private");
    let wrong_signature_public_key = root.join("keys").join("ml-dsa-002.public");

    pack_archive_with_recipients(
        &root,
        &input,
        &archive,
        SettingsOverrides::default(),
        std::slice::from_ref(&recipient_public_key),
    )
    .expect("pack encrypted archive");
    sign_archive(
        &archive,
        &signature_private_key,
        Some(SignaturePlacement::Detached),
        Some(&detached_signature),
    )
    .expect("sign encrypted archive with detached signature");

    let error = extract_archive_with_recipient(
        &archive,
        &output,
        Some(&wrong_signature_public_key),
        Some(&detached_signature),
        Some(&recipient_private_key),
    )
    .expect_err("extract should reject wrong signature public key");
    assert!(matches!(error, QsrlError::SignatureVerificationFailed(_)));
    assert!(!output.exists());
}

#[cfg(feature = "liboqs-backend")]
#[test]
fn encrypted_archive_detached_signature_rejects_wrong_recipient_key() {
    let root = fresh_temp_dir("encrypted-detached-wrong-recipient");
    let input = write_sample_input(&root);
    let archive = root.join("encrypted-detached-wrong-recipient.qsrl");
    let output = root.join("decrypted");
    let detached_signature = root.join("encrypted-detached-wrong-recipient.sig");

    recipient_keygen(&root, KemAlgorithm::MlKem).expect("generate recipient key");
    recipient_keygen(&root, KemAlgorithm::MlKem).expect("generate extra recipient key");
    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate signature key");
    let recipient_public_key = root.join("keys").join("ml-kem-001.public");
    let wrong_recipient_private_key = root.join("keys").join("ml-kem-002.private");
    let signature_private_key = root.join("keys").join("ml-dsa-001.private");
    let signature_public_key = root.join("keys").join("ml-dsa-001.public");

    pack_archive_with_recipients(
        &root,
        &input,
        &archive,
        SettingsOverrides::default(),
        std::slice::from_ref(&recipient_public_key),
    )
    .expect("pack encrypted archive");
    sign_archive(
        &archive,
        &signature_private_key,
        Some(SignaturePlacement::Detached),
        Some(&detached_signature),
    )
    .expect("sign encrypted archive with detached signature");

    let error = extract_archive_with_recipient(
        &archive,
        &output,
        Some(&signature_public_key),
        Some(&detached_signature),
        Some(&wrong_recipient_private_key),
    )
    .expect_err("extract should reject wrong recipient key");
    assert!(matches!(error, QsrlError::KeyRejected(_)));
    assert!(!output.exists());
}

#[cfg(feature = "liboqs-backend")]
#[test]
fn wrong_recipient_key_is_rejected() {
    let root = fresh_temp_dir("wrong-recipient");
    let input = write_sample_input(&root);
    let archive = root.join("wrong-recipient.qsrl");
    let output = root.join("decrypted");

    recipient_keygen(&root, KemAlgorithm::MlKem).expect("generate recipient key");
    recipient_keygen(&root, KemAlgorithm::MlKem).expect("generate extra recipient key");
    let recipient_public_key = root.join("keys").join("ml-kem-001.public");
    let wrong_private_key = root.join("keys").join("ml-kem-002.private");

    pack_archive_with_recipients(
        &root,
        &input,
        &archive,
        SettingsOverrides::default(),
        std::slice::from_ref(&recipient_public_key),
    )
    .expect("pack encrypted archive");

    let error =
        extract_archive_with_recipient(&archive, &output, None, None, Some(&wrong_private_key))
            .expect_err("extract should fail");
    assert!(matches!(error, QsrlError::KeyRejected(_)));
}

#[cfg(feature = "liboqs-backend")]
#[test]
fn corrupted_encrypted_ciphertext_is_detected() {
    let root = fresh_temp_dir("encrypted-corruption");
    let input = write_sample_input(&root);
    let archive = root.join("encrypted-corrupt.qsrl");
    let output = root.join("decrypted");

    recipient_keygen(&root, KemAlgorithm::MlKem).expect("generate recipient key");
    let recipient_private_key = root.join("keys").join("ml-kem-001.private");
    let recipient_public_key = root.join("keys").join("ml-kem-001.public");

    pack_archive_with_recipients(
        &root,
        &input,
        &archive,
        SettingsOverrides::default(),
        std::slice::from_ref(&recipient_public_key),
    )
    .expect("pack encrypted archive");

    let parsed = Archive::read_from_path(&archive).expect("read archive");
    let mut bytes = fs::read(&archive).expect("read encrypted bytes");
    let payload_offset = parsed.payload_offset();
    bytes[payload_offset] ^= 0x01;
    fs::write(&archive, bytes).expect("rewrite archive");

    let error =
        extract_archive_with_recipient(&archive, &output, None, None, Some(&recipient_private_key))
            .expect_err("extract should fail");
    assert!(matches!(error, QsrlError::DataCorruption(_)));
    assert!(!output.exists());
}

#[cfg(feature = "liboqs-backend")]
#[test]
fn signed_only_and_signed_plus_encrypted_archives_coexist() {
    let root = fresh_temp_dir("coexistence");
    let input = write_sample_input(&root);
    let plain_archive = root.join("plain.qsrl");
    let encrypted_archive = root.join("encrypted.qsrl");
    let encrypted_output = root.join("encrypted-output");

    keygen(&root, SignatureAlgorithm::MlDsa).expect("generate signature key");
    recipient_keygen(&root, KemAlgorithm::MlKem).expect("generate recipient key");
    let signature_private_key = root.join("keys").join("ml-dsa-001.private");
    let signature_public_key = root.join("keys").join("ml-dsa-001.public");
    let recipient_private_key = root.join("keys").join("ml-kem-001.private");
    let recipient_public_key = root.join("keys").join("ml-kem-001.public");

    pack_archive(&root, &input, &plain_archive, SettingsOverrides::default()).expect("pack plain");
    sign_archive(
        &plain_archive,
        &signature_private_key,
        Some(SignaturePlacement::Embedded),
        None,
    )
    .expect("sign plain archive");
    let plain_verify =
        verify_archive(&plain_archive, &signature_public_key, None).expect("verify plain archive");
    assert!(plain_verify.contains("file hashes: ok"));

    pack_archive_with_recipients(
        &root,
        &input,
        &encrypted_archive,
        SettingsOverrides::default(),
        std::slice::from_ref(&recipient_public_key),
    )
    .expect("pack encrypted");
    sign_archive(
        &encrypted_archive,
        &signature_private_key,
        Some(SignaturePlacement::Embedded),
        None,
    )
    .expect("sign encrypted archive");
    let encrypted_verify = verify_archive(&encrypted_archive, &signature_public_key, None)
        .expect("verify encrypted archive");
    assert!(
        encrypted_verify
            .contains("signature only; encrypted payload not authenticated until decrypt/extract")
    );

    extract_archive_with_recipient(
        &encrypted_archive,
        &encrypted_output,
        Some(&signature_public_key),
        None,
        Some(&recipient_private_key),
    )
    .expect("extract encrypted archive");
    assert_eq!(read_tree(&input), read_tree(&encrypted_output));
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
