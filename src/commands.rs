use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use crate::FORMAT_VERSION;
use crate::archive::{Archive, PackPlan, default_detached_signature_path};
use crate::config::RepoConfig;
use crate::crypto::{
    KeyImplementation, generate_keypair, load_private_key, load_public_key, message_digest,
    sign_message, verify_signature, write_private_key, write_public_key,
};
use crate::error::{QsrlError, Result};
use crate::protocol::{
    CompressionLayout, CompressionMode, ManifestEncoding, SignatureAlgorithm, SignaturePlacement,
    SignatureRecord, SignatureScope,
};
use crate::util::{ensure_parent_dir, unique_id, write_string};

#[derive(Clone, Debug, Default)]
pub struct SettingsOverrides {
    pub format_version: Option<u16>,
    pub signature_algorithm: Option<SignatureAlgorithm>,
    pub signature_placement: Option<SignaturePlacement>,
    pub signature_scope: Option<SignatureScope>,
    pub manifest_encoding: Option<ManifestEncoding>,
    pub compression_mode: Option<CompressionMode>,
    pub compression_layout: Option<CompressionLayout>,
}

pub fn init_repo(root: &Path, overrides: SettingsOverrides) -> Result<String> {
    let config = resolve_config(root, overrides)?;
    let path = config.save(root)?;
    Ok(format!(
        "initialized QSRL config at {}\nalgorithm: {}\nplacement: {}\nscope: {}\nmanifest encoding: {}\ncompression: {} / {}",
        path.display(),
        config.signature_algorithm.as_str(),
        config.signature_placement.as_str(),
        config.signature_scope.as_str(),
        config.manifest_encoding.as_str(),
        config.compression_mode.as_str(),
        config.compression_layout.as_str()
    ))
}

pub fn pack_archive(
    root: &Path,
    input_path: &Path,
    output_path: &Path,
    overrides: SettingsOverrides,
) -> Result<String> {
    let config = resolve_config(root, overrides)?;
    let plan = PackPlan {
        format_version: config.format_version,
        signature_algorithm: config.signature_algorithm,
        signature_placement: config.signature_placement,
        signature_scope: config.signature_scope,
        manifest_encoding: config.manifest_encoding,
        compression_mode: config.compression_mode,
        compression_layout: config.compression_layout,
    };
    let mut archive = Archive::build_from_path(input_path, &plan)?;
    archive.write_to_path(output_path)?;
    Ok(format!(
        "packed {} files into {}\nmanifest bytes: {}\nblock table bytes: {}\npayload bytes: {}\nsignature algorithm: {}\nsignature placement: {}\nmanifest scope: {}\ncompression: {} / {}",
        archive.manifest.files.len(),
        output_path.display(),
        archive.manifest_bytes.len(),
        archive.block_table_bytes.len(),
        archive.payload.len(),
        archive.manifest.signature_algorithm.as_str(),
        archive.manifest.signature_placement.as_str(),
        archive.manifest.signature_scope.as_str(),
        archive.manifest.compression_mode.as_str(),
        archive.manifest.compression_layout.as_str(),
    ))
}

pub fn keygen(root: &Path, algorithm: SignatureAlgorithm) -> Result<String> {
    let keys_dir = root.join("keys");
    fs::create_dir_all(&keys_dir).map_err(|err| QsrlError::io("creating keys directory", err))?;
    let key_id = next_key_id(&keys_dir, algorithm)?;
    let (private_key, public_key) = generate_keypair(algorithm, key_id.clone())?;
    let private_path = keys_dir.join(format!("{key_id}.private"));
    let public_path = keys_dir.join(format!("{key_id}.public"));
    write_private_key(&private_path, &private_key)?;
    write_public_key(&public_path, &public_key)?;
    let mut output = format!(
        "generated {} keypair\nprivate key: {}\npublic key: {}\nbackend: {}\nmethod: {}",
        algorithm.as_str(),
        private_path.display(),
        public_path.display(),
        private_key.implementation_label(),
        private_key.method_name,
    );
    if let Some(version) = &private_key.library_version {
        output.push_str(&format!("\nliboqs version: {version}"));
    }
    if matches!(private_key.implementation, KeyImplementation::StubLamportV1) {
        output.push_str(
            "\nnote: this build is using the prototype stub backend; rebuild with --features liboqs-backend for real liboqs signatures",
        );
    }
    Ok(output)
}

pub fn sign_archive(
    archive_path: &Path,
    key_path: &Path,
    placement_override: Option<SignaturePlacement>,
    signature_path: Option<&Path>,
) -> Result<String> {
    let mut archive = Archive::read_from_path(archive_path)?;
    let mut private_key = load_private_key(key_path)?;
    if private_key.algorithm != archive.manifest.signature_algorithm {
        return Err(QsrlError::UnsupportedAlgorithm(format!(
            "archive expects {} but private key is {}",
            archive.manifest.signature_algorithm.as_str(),
            private_key.algorithm.as_str()
        )));
    }

    let placement = placement_override.unwrap_or(archive.manifest.signature_placement);
    archive.set_signature_placement(placement)?;
    let signed_payload = archive.signed_payload()?;
    let signature_bytes = sign_message(&private_key, &signed_payload)?;
    let signature = SignatureRecord {
        algorithm: archive.manifest.signature_algorithm,
        scope: archive.manifest.signature_scope,
        implementation: private_key.implementation_code(),
        public_key_fingerprint: private_key.public_key_fingerprint,
        signed_payload_digest: message_digest(&signed_payload),
        signature: signature_bytes,
    };

    private_key.uses = private_key.uses.saturating_add(1);
    write_private_key(key_path, &private_key)?;
    let reuse_note =
        if private_key.implementation == KeyImplementation::StubLamportV1 && private_key.uses > 1 {
            "\nwarning: stub-lamport-v1 key reuse is allowed for workflow testing only"
        } else {
            ""
        };

    match placement {
        SignaturePlacement::Embedded => {
            archive.set_embedded_signature(signature);
            archive.write_to_path(archive_path)?;
            Ok(format!(
                "embedded signature into {}\nsigned payload bytes: {}\nkey uses recorded: {}\nbackend: {}{}",
                archive_path.display(),
                signed_payload.len(),
                private_key.uses,
                private_key.implementation_label(),
                reuse_note,
            ))
        }
        SignaturePlacement::Detached => {
            archive.write_to_path(archive_path)?;
            let output_path = signature_path
                .map(PathBuf::from)
                .unwrap_or_else(|| default_detached_signature_path(archive_path));
            ensure_parent_dir(&output_path)?;
            fs::write(&output_path, signature.serialize()).map_err(|err| {
                QsrlError::io(
                    format!("writing detached signature {}", output_path.display()),
                    err,
                )
            })?;
            Ok(format!(
                "wrote detached signature {}\narchive updated: {}\nsigned payload bytes: {}\nkey uses recorded: {}\nbackend: {}{}",
                output_path.display(),
                archive_path.display(),
                signed_payload.len(),
                private_key.uses,
                private_key.implementation_label(),
                reuse_note,
            ))
        }
    }
}

pub fn verify_archive(
    archive_path: &Path,
    public_key_path: &Path,
    signature_path: Option<&Path>,
) -> Result<String> {
    let archive = Archive::read_from_path(archive_path)?;
    let signature_status =
        verify_archive_signature(&archive, archive_path, public_key_path, signature_path)?;
    archive.verify_file_hashes()?;

    Ok(format!(
        "verified {}\n{}\nfile hashes: ok\nfiles checked: {}\nplacement: {}\nalgorithm: {}",
        archive_path.display(),
        signature_status,
        archive.manifest.files.len(),
        archive.manifest.signature_placement.as_str(),
        archive.manifest.signature_algorithm.as_str(),
    ))
}

pub fn extract_archive(
    archive_path: &Path,
    output_dir: &Path,
    public_key_path: Option<&Path>,
    signature_path: Option<&Path>,
) -> Result<String> {
    let archive = Archive::read_from_path(archive_path)?;
    let signature_status = if let Some(public_key_path) = public_key_path {
        Some(verify_archive_signature(
            &archive,
            archive_path,
            public_key_path,
            signature_path,
        )?)
    } else if archive.signature.is_some()
        || archive.manifest.signature_placement == SignaturePlacement::Detached
    {
        Some("signature: not checked (no --pubkey provided)".into())
    } else {
        None
    };

    let files = archive.extract_files()?;
    archive.verify_decoded_files(&files)?;
    let relative_paths = planned_output_paths(&archive, output_dir)?;

    fs::create_dir_all(output_dir)
        .map_err(|err| QsrlError::io(format!("creating {}", output_dir.display()), err))?;

    for (relative_path, data) in relative_paths.iter().zip(files.iter()) {
        let destination = output_dir.join(relative_path);
        ensure_parent_dir(&destination)?;
        fs::write(&destination, data)
            .map_err(|err| QsrlError::io(format!("writing {}", destination.display()), err))?;
    }

    let mut output = format!(
        "extracted {} files to {}\nfile hashes: ok",
        archive.manifest.files.len(),
        output_dir.display()
    );
    if let Some(status) = signature_status {
        output.push_str(&format!("\n{status}"));
    }
    Ok(output)
}

pub fn inspect_archive(archive_path: &Path) -> Result<String> {
    let archive = Archive::read_from_path(archive_path)?;
    let detached_path = default_detached_signature_path(archive_path);
    let detached_present = archive.manifest.signature_placement == SignaturePlacement::Detached
        && detached_path.exists();
    let signature_status = match archive.manifest.signature_placement {
        SignaturePlacement::Embedded if archive.signature.is_some() => "embedded signature present",
        SignaturePlacement::Embedded => "embedded signature missing",
        SignaturePlacement::Detached if detached_present => "detached signature present",
        SignaturePlacement::Detached => "detached signature not found",
    };

    let mut output = String::new();
    output.push_str(&format!("archive: {}\n", archive_path.display()));
    output.push_str(&format!(
        "format version: {}\n",
        archive.manifest.format_version
    ));
    output.push_str(&format!(
        "signature algorithm: {}\n",
        archive.manifest.signature_algorithm.as_str()
    ));
    output.push_str(&format!(
        "signature placement: {}\n",
        archive.manifest.signature_placement.as_str()
    ));
    output.push_str(&format!(
        "signature scope: {}\n",
        archive.manifest.signature_scope.as_str()
    ));
    output.push_str(&format!(
        "manifest encoding: {}\n",
        archive.manifest.manifest_encoding.as_str()
    ));
    output.push_str(&format!(
        "compression: {} / {}\n",
        archive.manifest.compression_mode.as_str(),
        archive.manifest.compression_layout.as_str()
    ));
    output.push_str(&format!(
        "manifest bytes: {}\n",
        archive.manifest_bytes.len()
    ));
    output.push_str(&format!(
        "block table bytes: {}\n",
        archive.block_table_bytes.len()
    ));
    output.push_str(&format!("payload bytes: {}\n", archive.payload.len()));
    output.push_str(&format!("signature status: {signature_status}\n"));
    output.push_str(&format!("files: {}\n", archive.manifest.files.len()));
    for entry in &archive.manifest.files {
        output.push_str(&format!(
            "- {} ({} bytes, sha256 {}, compression {})\n",
            entry.path,
            entry.size,
            crate::util::hex_encode(&entry.sha256),
            entry.compression.as_str()
        ));
    }
    Ok(output)
}

pub fn compare_protocols(
    root: &Path,
    input_path: &Path,
    output_dir: &Path,
    key_path: &Path,
) -> Result<String> {
    fs::create_dir_all(output_dir)
        .map_err(|err| QsrlError::io(format!("creating {}", output_dir.display()), err))?;

    let private_key = load_private_key(key_path)?;
    let base = SettingsOverrides {
        signature_algorithm: Some(private_key.algorithm),
        signature_scope: Some(SignatureScope::Manifest),
        manifest_encoding: Some(ManifestEncoding::TextV1),
        compression_mode: Some(CompressionMode::None),
        compression_layout: Some(CompressionLayout::PerFile),
        ..SettingsOverrides::default()
    };

    let experiment1_embedded = output_dir.join("experiment1-embedded.qsrl");
    pack_archive(
        root,
        input_path,
        &experiment1_embedded,
        SettingsOverrides {
            signature_placement: Some(SignaturePlacement::Embedded),
            ..base.clone()
        },
    )?;
    sign_archive(
        &experiment1_embedded,
        key_path,
        Some(SignaturePlacement::Embedded),
        None,
    )?;
    let embedded_bytes = fs::metadata(&experiment1_embedded)
        .map_err(|err| QsrlError::io("reading embedded archive metadata", err))?
        .len();

    let experiment1_detached = output_dir.join("experiment1-detached.qsrl");
    pack_archive(
        root,
        input_path,
        &experiment1_detached,
        SettingsOverrides {
            signature_placement: Some(SignaturePlacement::Detached),
            ..base.clone()
        },
    )?;
    sign_archive(
        &experiment1_detached,
        key_path,
        Some(SignaturePlacement::Detached),
        None,
    )?;
    let detached_archive_bytes = fs::metadata(&experiment1_detached)
        .map_err(|err| QsrlError::io("reading detached archive metadata", err))?
        .len();
    let detached_sig_path = default_detached_signature_path(&experiment1_detached);
    let detached_sig_bytes = fs::metadata(&detached_sig_path)
        .map_err(|err| QsrlError::io("reading detached signature metadata", err))?
        .len();

    let manifest_text_path = output_dir.join("experiment2-manifest-text.qsrl");
    pack_archive(
        root,
        input_path,
        &manifest_text_path,
        SettingsOverrides {
            manifest_encoding: Some(ManifestEncoding::TextV1),
            ..base.clone()
        },
    )?;
    let manifest_text_archive = Archive::read_from_path(&manifest_text_path)?;

    let manifest_binary_path = output_dir.join("experiment2-manifest-binary.qsrl");
    pack_archive(
        root,
        input_path,
        &manifest_binary_path,
        SettingsOverrides {
            manifest_encoding: Some(ManifestEncoding::BinaryV1),
            ..base.clone()
        },
    )?;
    let manifest_binary_archive = Archive::read_from_path(&manifest_binary_path)?;

    let compression_none_path = output_dir.join("experiment3-none.qsrl");
    let none_started = Instant::now();
    pack_archive(
        root,
        input_path,
        &compression_none_path,
        SettingsOverrides {
            compression_mode: Some(CompressionMode::None),
            compression_layout: Some(CompressionLayout::PerFile),
            ..base.clone()
        },
    )?;
    let none_elapsed = none_started.elapsed();
    let none_bytes = fs::metadata(&compression_none_path)
        .map_err(|err| QsrlError::io("reading none compression metadata", err))?
        .len();

    let compression_per_file_path = output_dir.join("experiment3-rle-per-file.qsrl");
    let per_file_started = Instant::now();
    pack_archive(
        root,
        input_path,
        &compression_per_file_path,
        SettingsOverrides {
            compression_mode: Some(CompressionMode::Rle),
            compression_layout: Some(CompressionLayout::PerFile),
            ..base.clone()
        },
    )?;
    let per_file_elapsed = per_file_started.elapsed();
    let per_file_bytes = fs::metadata(&compression_per_file_path)
        .map_err(|err| QsrlError::io("reading per-file compression metadata", err))?
        .len();

    let compression_whole_path = output_dir.join("experiment3-rle-whole-archive.qsrl");
    let whole_started = Instant::now();
    pack_archive(
        root,
        input_path,
        &compression_whole_path,
        SettingsOverrides {
            compression_mode: Some(CompressionMode::Rle),
            compression_layout: Some(CompressionLayout::WholeArchive),
            ..base
        },
    )?;
    let whole_elapsed = whole_started.elapsed();
    let whole_bytes = fs::metadata(&compression_whole_path)
        .map_err(|err| QsrlError::io("reading whole-archive compression metadata", err))?
        .len();

    let report_path = output_dir.join("comparison.txt");
    let mut report = format!(
        "Quantum Sealed Record Layer comparison report\nrun id: {}\n\n\
Experiment 1: embedded vs detached signatures\n\
- embedded archive: {} bytes ({})\n\
- detached archive: {} bytes ({})\n\
- detached signature: {} bytes ({})\n\
- detached total: {} bytes\n\
\n\
Tradeoff note: embedded signatures keep a single artifact, while detached signatures leave the unsigned container bytes untouched and make signature replacement simpler.\n\
\n\
Experiment 2: canonical manifest serialization\n\
- text manifest bytes: {} ({})\n\
- text archive bytes: {}\n\
- binary manifest bytes: {} ({})\n\
- binary archive bytes: {}\n\
\n\
Tradeoff note: text-v1 is easier to inspect by eye, while binary-v1 is smaller and stricter to parse.\n\
\n\
Experiment 3: compression layout\n\
- none/per-file: {} bytes, packed in {} ms ({})\n\
- rle/per-file: {} bytes, packed in {} ms ({})\n\
- rle/whole-archive: {} bytes, packed in {} ms ({})\n\
\n\
Tradeoff note: whole-archive compression can improve size on repetitive trees, while per-file layout keeps block boundaries explicit for future extraction and random-access work.\n\
",
        unique_id(),
        embedded_bytes,
        experiment1_embedded.display(),
        detached_archive_bytes,
        experiment1_detached.display(),
        detached_sig_bytes,
        detached_sig_path.display(),
        detached_archive_bytes + detached_sig_bytes,
        manifest_text_archive.manifest_bytes.len(),
        manifest_text_path.display(),
        fs::metadata(&manifest_text_path)
            .map_err(|err| QsrlError::io("reading text manifest metadata", err))?
            .len(),
        manifest_binary_archive.manifest_bytes.len(),
        manifest_binary_path.display(),
        fs::metadata(&manifest_binary_path)
            .map_err(|err| QsrlError::io("reading binary manifest metadata", err))?
            .len(),
        none_bytes,
        none_elapsed.as_millis(),
        compression_none_path.display(),
        per_file_bytes,
        per_file_elapsed.as_millis(),
        compression_per_file_path.display(),
        whole_bytes,
        whole_elapsed.as_millis(),
        compression_whole_path.display(),
    );
    if private_key.implementation == KeyImplementation::StubLamportV1 {
        report = report.replace(
            "\nExperiment 2: canonical manifest serialization\n",
            "\nPrototype note: the comparison harness reused a stub-lamport-v1 key for convenience; that is suitable for workflow testing but not a security claim.\n\nExperiment 2: canonical manifest serialization\n",
        );
    }
    write_string(&report_path, &report)?;

    Ok(format!(
        "wrote comparison report to {}\nartifacts directory: {}",
        report_path.display(),
        output_dir.display(),
    ))
}

fn resolve_config(root: &Path, overrides: SettingsOverrides) -> Result<RepoConfig> {
    let mut config = RepoConfig::load_or_default(root)?;
    if let Some(format_version) = overrides.format_version {
        config.format_version = format_version;
    }
    if config.format_version != FORMAT_VERSION {
        return Err(QsrlError::UnsupportedVersion(config.format_version));
    }
    if let Some(value) = overrides.signature_algorithm {
        config.signature_algorithm = value;
    }
    if let Some(value) = overrides.signature_placement {
        config.signature_placement = value;
    }
    if let Some(value) = overrides.signature_scope {
        config.signature_scope = value;
    }
    if let Some(value) = overrides.manifest_encoding {
        config.manifest_encoding = value;
    }
    if let Some(value) = overrides.compression_mode {
        config.compression_mode = value;
    }
    if let Some(value) = overrides.compression_layout {
        config.compression_layout = value;
    }
    Ok(config)
}

fn next_key_id(keys_dir: &Path, algorithm: SignatureAlgorithm) -> Result<String> {
    let prefix = format!("{}-", algorithm.as_str());
    let mut next_index = 1usize;
    if keys_dir.exists() {
        for entry in fs::read_dir(keys_dir)
            .map_err(|err| QsrlError::io(format!("reading {}", keys_dir.display()), err))?
        {
            let entry = entry.map_err(|err| QsrlError::io("reading key entry", err))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(&prefix) || !name.ends_with(".private") {
                continue;
            }
            let stem = name.trim_end_matches(".private");
            if let Some(number_text) = stem.strip_prefix(&prefix) {
                if let Ok(number) = number_text.parse::<usize>() {
                    next_index = next_index.max(number + 1);
                }
            }
        }
    }
    Ok(format!("{}-{:03}", algorithm.as_str(), next_index))
}

fn verify_archive_signature(
    archive: &Archive,
    archive_path: &Path,
    public_key_path: &Path,
    signature_path: Option<&Path>,
) -> Result<String> {
    let public_key = load_public_key(public_key_path)?;
    if public_key.algorithm != archive.manifest.signature_algorithm {
        return Err(QsrlError::UnsupportedAlgorithm(format!(
            "archive expects {} but public key is {}",
            archive.manifest.signature_algorithm.as_str(),
            public_key.algorithm.as_str()
        )));
    }

    let signature = load_signature_record(archive, archive_path, signature_path)?;
    if signature.implementation != public_key.implementation_code() {
        return Err(QsrlError::SignatureVerificationFailed(format!(
            "signature implementation code {} did not match the provided public key backend {}",
            signature.implementation,
            public_key.implementation_label()
        )));
    }
    if signature.algorithm != archive.manifest.signature_algorithm {
        return Err(QsrlError::SignatureVerificationFailed(
            "signature algorithm does not match archive manifest".into(),
        ));
    }
    if signature.scope != archive.manifest.signature_scope {
        return Err(QsrlError::SignatureVerificationFailed(
            "signature scope does not match archive manifest".into(),
        ));
    }
    if signature.public_key_fingerprint != public_key.fingerprint {
        return Err(QsrlError::SignatureVerificationFailed(
            "public key fingerprint did not match the signature record".into(),
        ));
    }

    let signed_payload = archive.signed_payload()?;
    let expected_digest = message_digest(&signed_payload);
    if expected_digest != signature.signed_payload_digest {
        return Err(QsrlError::SignatureVerificationFailed(
            "signed payload digest did not match the canonical archive state".into(),
        ));
    }
    verify_signature(&public_key, &signed_payload, &signature.signature)?;
    Ok("signature: ok".into())
}

fn load_signature_record(
    archive: &Archive,
    archive_path: &Path,
    signature_path: Option<&Path>,
) -> Result<SignatureRecord> {
    match archive.manifest.signature_placement {
        SignaturePlacement::Embedded => archive.signature.clone().ok_or_else(|| {
            QsrlError::MissingSignature("embedded signature block is missing".into())
        }),
        SignaturePlacement::Detached => {
            let path = signature_path
                .map(PathBuf::from)
                .unwrap_or_else(|| default_detached_signature_path(archive_path));
            if !path.exists() {
                return Err(QsrlError::MissingSignature(format!(
                    "detached signature file not found at {}",
                    path.display()
                )));
            }
            SignatureRecord::deserialize(
                &fs::read(&path)
                    .map_err(|err| QsrlError::io(format!("reading {}", path.display()), err))?,
            )
        }
    }
}

fn planned_output_paths(archive: &Archive, output_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::with_capacity(archive.manifest.files.len());
    let mut seen = BTreeSet::new();

    for entry in &archive.manifest.files {
        let relative = safe_output_relative_path(&entry.path)?;
        if !seen.insert(relative.clone()) {
            return Err(QsrlError::InvalidFormat(format!(
                "archive contains duplicate extraction path '{}'",
                relative.display()
            )));
        }

        let destination = output_dir.join(&relative);
        if !destination.starts_with(output_dir) {
            return Err(QsrlError::InvalidFormat(format!(
                "archive path '{}' would escape the output directory",
                entry.path
            )));
        }
        paths.push(relative);
    }

    Ok(paths)
}

fn safe_output_relative_path(path_text: &str) -> Result<PathBuf> {
    if path_text.contains('\\') {
        return Err(QsrlError::InvalidFormat(format!(
            "archive path '{}' is not normalized for extraction",
            path_text
        )));
    }

    let mut normalized = PathBuf::new();
    for component in Path::new(path_text).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(QsrlError::InvalidFormat(format!(
                    "archive path '{}' would escape the output directory",
                    path_text
                )));
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(QsrlError::InvalidFormat(
            "archive contains an empty extraction path".into(),
        ));
    }

    Ok(normalized)
}
