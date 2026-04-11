use std::path::{Path, PathBuf};

use crate::archive::{Archive, default_detached_signature_path};
use crate::commands::{
    self, SettingsOverrides, extract_archive_with_recipient, keygen, pack_archive_with_recipients,
    recipient_keygen, sign_archive, verify_archive_signature,
};
use crate::error::{QsrlError, Result};
use crate::protocol::{
    CompressionLayout, CompressionMode, KemAlgorithm, ManifestEncoding, SignatureAlgorithm,
    SignaturePlacement,
};
use crate::util::{collect_input_files, hex_encode};

#[derive(Clone, Debug)]
pub struct PackRequest {
    pub root: PathBuf,
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub settings: SettingsOverrides,
    pub recipient_key_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct SignRequest {
    pub archive_path: PathBuf,
    pub key_path: PathBuf,
    pub placement_override: Option<SignaturePlacement>,
    pub signature_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct VerifyRequest {
    pub archive_path: PathBuf,
    pub public_key_path: PathBuf,
    pub signature_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ExtractRequest {
    pub archive_path: PathBuf,
    pub output_dir: PathBuf,
    pub public_key_path: Option<PathBuf>,
    pub signature_path: Option<PathBuf>,
    pub recipient_key_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct InspectRequest {
    pub archive_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeygenAlgorithm {
    MlDsa,
    SlhDsa,
    MlKemRecipient,
}

impl KeygenAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa => "ml-dsa",
            Self::SlhDsa => "slh-dsa",
            Self::MlKemRecipient => "ml-kem",
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeygenRequest {
    pub output_root: PathBuf,
    pub algorithm: KeygenAlgorithm,
}

#[derive(Clone, Debug)]
pub struct VerifyReport {
    pub archive_path: PathBuf,
    pub signature_status: String,
    pub file_hash_status: String,
    pub files_checked: usize,
    pub placement: SignaturePlacement,
    pub algorithm: SignatureAlgorithm,
    pub log: String,
}

#[derive(Clone, Debug)]
pub struct InspectFileSummary {
    pub path: String,
    pub size: u64,
    pub sha256_hex: String,
    pub compression: CompressionMode,
}

#[derive(Clone, Debug)]
pub struct InspectReport {
    pub archive_path: PathBuf,
    pub format_version: u16,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature_placement: SignaturePlacement,
    pub signature_scope: String,
    pub manifest_encoding: ManifestEncoding,
    pub compression_mode: CompressionMode,
    pub compression_layout: CompressionLayout,
    pub encrypted: bool,
    pub recipient_count: usize,
    pub kem_method: Option<String>,
    pub aead_method: Option<String>,
    pub signature_status: String,
    pub files: Vec<InspectFileSummary>,
    pub log: String,
}

#[derive(Clone, Debug)]
pub struct KeygenReport {
    pub output_root: PathBuf,
    pub keys_dir: PathBuf,
    pub algorithm: KeygenAlgorithm,
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub log: String,
}

pub fn validate_pack_request(request: &PackRequest) -> Result<()> {
    ensure_existing_directory(&request.input_path, "input folder")?;
    ensure_qsrl_output_path(&request.output_path)?;
    for path in &request.recipient_key_paths {
        ensure_existing_file(path, "recipient public key")?;
    }
    Ok(())
}

pub fn validate_sign_request(request: &SignRequest) -> Result<()> {
    ensure_existing_file(&request.archive_path, "archive file")?;
    ensure_existing_file(&request.key_path, "signing private key")?;
    if let Some(signature_path) = &request.signature_path {
        ensure_non_empty_path(signature_path, "detached signature path")?;
    }
    Ok(())
}

pub fn validate_verify_request(request: &VerifyRequest) -> Result<()> {
    ensure_existing_file(&request.archive_path, "archive file")?;
    ensure_existing_file(&request.public_key_path, "signing public key")?;
    if let Some(signature_path) = &request.signature_path {
        ensure_existing_file(signature_path, "detached signature file")?;
    }
    Ok(())
}

pub fn validate_extract_request(request: &ExtractRequest) -> Result<()> {
    ensure_existing_file(&request.archive_path, "archive file")?;
    ensure_non_empty_path(&request.output_dir, "output directory")?;
    if request.output_dir.exists() && !request.output_dir.is_dir() {
        return Err(QsrlError::Usage(format!(
            "output directory path points to a file: {}",
            request.output_dir.display()
        )));
    }
    if let Some(public_key_path) = &request.public_key_path {
        ensure_existing_file(public_key_path, "signing public key")?;
    }
    if let Some(signature_path) = &request.signature_path {
        ensure_existing_file(signature_path, "detached signature file")?;
    }
    if let Some(recipient_key_path) = &request.recipient_key_path {
        ensure_existing_file(recipient_key_path, "recipient private key")?;
    }
    Ok(())
}

pub fn validate_inspect_request(request: &InspectRequest) -> Result<()> {
    ensure_existing_file(&request.archive_path, "archive file")
}

pub fn validate_keygen_request(request: &KeygenRequest) -> Result<()> {
    ensure_non_empty_path(&request.output_root, "output root")?;
    if request.output_root.exists() && !request.output_root.is_dir() {
        return Err(QsrlError::Usage(format!(
            "output root points to a file: {}",
            request.output_root.display()
        )));
    }
    Ok(())
}

pub fn run_pack(request: &PackRequest) -> Result<String> {
    validate_pack_request(request)?;
    pack_archive_with_recipients(
        &request.root,
        &request.input_path,
        &request.output_path,
        request.settings.clone(),
        &request.recipient_key_paths,
    )
}

pub fn pack_input_file_count(input_path: &Path) -> Result<usize> {
    Ok(collect_input_files(input_path)?.len())
}

pub fn run_keygen(request: &KeygenRequest) -> Result<KeygenReport> {
    validate_keygen_request(request)?;
    let log = match request.algorithm {
        KeygenAlgorithm::MlDsa => keygen(&request.output_root, SignatureAlgorithm::MlDsa)?,
        KeygenAlgorithm::SlhDsa => keygen(&request.output_root, SignatureAlgorithm::SlhDsa)?,
        KeygenAlgorithm::MlKemRecipient => {
            recipient_keygen(&request.output_root, KemAlgorithm::MlKem)?
        }
    };
    let private_key_path = generated_key_path(&log, "private key: ")?;
    let public_key_path = generated_key_path(&log, "public key: ")?;

    Ok(KeygenReport {
        output_root: request.output_root.clone(),
        keys_dir: request.output_root.join("keys"),
        algorithm: request.algorithm,
        private_key_path,
        public_key_path,
        log,
    })
}

pub fn run_sign(request: &SignRequest) -> Result<String> {
    validate_sign_request(request)?;
    sign_archive(
        &request.archive_path,
        &request.key_path,
        request.placement_override,
        request.signature_path.as_deref(),
    )
}

pub fn run_extract(request: &ExtractRequest) -> Result<String> {
    validate_extract_request(request)?;
    extract_archive_with_recipient(
        &request.archive_path,
        &request.output_dir,
        request.public_key_path.as_deref(),
        request.signature_path.as_deref(),
        request.recipient_key_path.as_deref(),
    )
}

pub fn verify_report(request: &VerifyRequest) -> Result<VerifyReport> {
    validate_verify_request(request)?;
    let archive = Archive::read_from_path(&request.archive_path)?;
    let signature_status = verify_archive_signature(
        &archive,
        &request.archive_path,
        &request.public_key_path,
        request.signature_path.as_deref(),
    )?;
    let file_hash_status = if archive.is_encrypted() {
        "not checked".to_string()
    } else {
        archive.verify_file_hashes()?;
        "ok".to_string()
    };
    let log = if archive.is_encrypted() {
        format!(
            "verified {}\n{}\nfile hashes: not checked (encrypted payload; use qsrl extract --recipient-key to decrypt and verify contents)\nfiles checked: {}\nplacement: {}\nalgorithm: {}",
            request.archive_path.display(),
            signature_status,
            archive.manifest.files.len(),
            archive.manifest.signature_placement.as_str(),
            archive.manifest.signature_algorithm.as_str(),
        )
    } else {
        format!(
            "verified {}\n{}\nfile hashes: ok\nfiles checked: {}\nplacement: {}\nalgorithm: {}",
            request.archive_path.display(),
            signature_status,
            archive.manifest.files.len(),
            archive.manifest.signature_placement.as_str(),
            archive.manifest.signature_algorithm.as_str(),
        )
    };

    Ok(VerifyReport {
        archive_path: request.archive_path.clone(),
        signature_status,
        file_hash_status,
        files_checked: archive.manifest.files.len(),
        placement: archive.manifest.signature_placement,
        algorithm: archive.manifest.signature_algorithm,
        log,
    })
}

pub fn inspect_report(request: &InspectRequest) -> Result<InspectReport> {
    validate_inspect_request(request)?;
    let archive = Archive::read_from_path(&request.archive_path)?;
    let detached_path = default_detached_signature_path(&request.archive_path);
    let detached_present = archive.manifest.signature_placement == SignaturePlacement::Detached
        && detached_path.exists();
    let signature_status = match archive.manifest.signature_placement {
        SignaturePlacement::Embedded if archive.signature.is_some() => {
            "embedded signature present".to_string()
        }
        SignaturePlacement::Embedded => "embedded signature missing".to_string(),
        SignaturePlacement::Detached if detached_present => {
            "detached signature present".to_string()
        }
        SignaturePlacement::Detached => "detached signature not found".to_string(),
    };
    let files = archive
        .manifest
        .files
        .iter()
        .map(|entry| InspectFileSummary {
            path: entry.path.clone(),
            size: entry.size,
            sha256_hex: hex_encode(&entry.sha256),
            compression: entry.compression,
        })
        .collect();
    let log = commands::inspect_archive(&request.archive_path)?;

    Ok(InspectReport {
        archive_path: request.archive_path.clone(),
        format_version: archive.manifest.format_version,
        signature_algorithm: archive.manifest.signature_algorithm,
        signature_placement: archive.manifest.signature_placement,
        signature_scope: archive.manifest.signature_scope.as_str().to_string(),
        manifest_encoding: archive.manifest.manifest_encoding,
        compression_mode: archive.manifest.compression_mode,
        compression_layout: archive.manifest.compression_layout,
        encrypted: archive.encryption.is_some(),
        recipient_count: archive
            .encryption
            .as_ref()
            .map(|section| section.recipients.len())
            .unwrap_or(0),
        kem_method: archive
            .encryption
            .as_ref()
            .map(|section| section.kem_method_name.clone()),
        aead_method: archive
            .encryption
            .as_ref()
            .map(|section| section.aead_algorithm.as_str().to_string()),
        signature_status,
        files,
        log,
    })
}

fn ensure_non_empty_path(path: &Path, label: &str) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(QsrlError::Usage(format!("choose a {label}")));
    }
    Ok(())
}

fn ensure_existing_file(path: &Path, label: &str) -> Result<()> {
    ensure_non_empty_path(path, label)?;
    if !path.is_file() {
        return Err(QsrlError::Usage(format!(
            "{label} not found at {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_existing_directory(path: &Path, label: &str) -> Result<()> {
    ensure_non_empty_path(path, label)?;
    if !path.is_dir() {
        return Err(QsrlError::Usage(format!(
            "{label} not found at {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_qsrl_output_path(path: &Path) -> Result<()> {
    ensure_non_empty_path(path, "output archive path")?;
    if path.extension().and_then(|value| value.to_str()) != Some("qsrl") {
        return Err(QsrlError::Usage(format!(
            "output archive should use the .qsrl extension: {}",
            path.display()
        )));
    }
    Ok(())
}

fn generated_key_path(log: &str, prefix: &str) -> Result<PathBuf> {
    let value = log
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .ok_or_else(|| QsrlError::Parse(format!("missing '{prefix}' in key generation output")))?;
    Ok(PathBuf::from(value.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::pack_archive;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "qsrl-ui-bridge-{name}-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn pack_validation_requires_existing_input_directory() {
        let request = PackRequest {
            root: PathBuf::from("."),
            input_path: PathBuf::from("missing-input"),
            output_path: PathBuf::from("archive.qsrl"),
            settings: SettingsOverrides::default(),
            recipient_key_paths: Vec::new(),
        };

        let error = validate_pack_request(&request).expect_err("validation should fail");
        assert!(matches!(error, QsrlError::Usage(_)));
    }

    #[test]
    fn pack_validation_requires_qsrl_extension() {
        let root = temp_root("pack-extension");
        let input = root.join("input");
        fs::create_dir_all(&input).expect("create input");
        let request = PackRequest {
            root: root.clone(),
            input_path: input,
            output_path: root.join("archive.zip"),
            settings: SettingsOverrides::default(),
            recipient_key_paths: Vec::new(),
        };

        let error = validate_pack_request(&request).expect_err("validation should fail");
        assert!(matches!(error, QsrlError::Usage(_)));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn inspect_report_summarizes_archive_metadata() {
        let root = temp_root("inspect");
        let input = root.join("input");
        let archive_path = root.join("sample.qsrl");
        fs::create_dir_all(&input).expect("create input");
        fs::write(input.join("hello.txt"), b"hello qsrl").expect("write sample file");
        pack_archive(&root, &input, &archive_path, SettingsOverrides::default())
            .expect("pack archive");

        let report = inspect_report(&InspectRequest {
            archive_path: archive_path.clone(),
        })
        .expect("inspect report");

        assert_eq!(report.archive_path, archive_path);
        assert_eq!(report.format_version, 1);
        assert_eq!(report.files.len(), 1);
        assert!(!report.encrypted);
        assert_eq!(report.files[0].path, "hello.txt");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pack_input_file_count_reports_zero_for_empty_directory() {
        let root = temp_root("empty-input");
        fs::create_dir_all(&root).expect("create directory");

        let count = pack_input_file_count(&root).expect("count input files");
        assert_eq!(count, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn run_keygen_creates_signature_keys_in_keys_directory() {
        let root = temp_root("keygen");
        fs::create_dir_all(&root).expect("create root");

        let report = run_keygen(&KeygenRequest {
            output_root: root.clone(),
            algorithm: KeygenAlgorithm::MlDsa,
        })
        .expect("run keygen");

        assert_eq!(report.algorithm, KeygenAlgorithm::MlDsa);
        assert!(report.private_key_path.exists());
        assert!(report.public_key_path.exists());
        assert!(report.private_key_path.starts_with(root.join("keys")));
        assert!(report.public_key_path.starts_with(root.join("keys")));

        let _ = fs::remove_dir_all(root);
    }
}
