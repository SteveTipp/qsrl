use std::str::FromStr;

use crate::FORMAT_VERSION;
use crate::error::{QsrlError, Result};
use crate::util::{
    hex_decode, hex_encode, push_u16_le, push_u32_le, push_u64_le, read_u16_le, read_u32_le,
    read_u64_le, take_bytes,
};

const MANIFEST_BINARY_MAGIC: &[u8; 4] = b"QMAN";
const BLOCK_TABLE_MAGIC: &[u8; 4] = b"QBLK";
const ARCHIVE_MAGIC: &[u8; 4] = b"QSRL";
const SIGNATURE_MAGIC: &[u8; 4] = b"QSIG";
const ENCRYPTION_MAGIC: &[u8; 4] = b"QENC";

pub const ARCHIVE_FLAG_EMBEDDED_SIGNATURE: u8 = 0x01;
pub const ARCHIVE_FLAG_ENCRYPTED_PAYLOAD: u8 = 0x02;
pub const MAX_MANIFEST_FILES: usize = 100_000;
pub const MAX_BLOCK_ENTRIES: usize = 100_000;
pub const MAX_RECIPIENT_RECORDS: usize = 1_024;

const BINARY_MANIFEST_PREFIX_LEN: usize = 18;
const MIN_BINARY_FILE_ENTRY_LEN: usize = 43;
const BLOCK_TABLE_PREFIX_LEN: usize = 10;
const BLOCK_ENTRY_LEN: usize = 40;
const MIN_RECIPIENT_RECORD_LEN: usize = 44;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    MlDsa,
    SlhDsa,
}

impl SignatureAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa => "ml-dsa",
            Self::SlhDsa => "slh-dsa",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::MlDsa => 1,
            Self::SlhDsa => 2,
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::MlDsa),
            2 => Ok(Self::SlhDsa),
            other => Err(QsrlError::UnsupportedAlgorithm(format!(
                "unsupported signature algorithm code {other}"
            ))),
        }
    }
}

impl FromStr for SignatureAlgorithm {
    type Err = QsrlError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "ml-dsa" => Ok(Self::MlDsa),
            "slh-dsa" => Ok(Self::SlhDsa),
            other => Err(QsrlError::UnsupportedAlgorithm(format!(
                "unsupported signature algorithm '{other}'"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignaturePlacement {
    Embedded,
    Detached,
}

impl SignaturePlacement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Detached => "detached",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Embedded => 1,
            Self::Detached => 2,
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Embedded),
            2 => Ok(Self::Detached),
            other => Err(QsrlError::Parse(format!(
                "unsupported signature placement code {other}"
            ))),
        }
    }
}

impl FromStr for SignaturePlacement {
    type Err = QsrlError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "embedded" => Ok(Self::Embedded),
            "detached" => Ok(Self::Detached),
            other => Err(QsrlError::Parse(format!(
                "unsupported signature placement '{other}'"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureScope {
    Manifest,
    ManifestAndBlockTable,
    PerFileExperimental,
}

impl SignatureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::ManifestAndBlockTable => "manifest+block-table",
            Self::PerFileExperimental => "per-file",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Manifest => 1,
            Self::ManifestAndBlockTable => 2,
            Self::PerFileExperimental => 3,
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Manifest),
            2 => Ok(Self::ManifestAndBlockTable),
            3 => Ok(Self::PerFileExperimental),
            other => Err(QsrlError::Parse(format!(
                "unsupported signature scope code {other}"
            ))),
        }
    }
}

impl FromStr for SignatureScope {
    type Err = QsrlError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "manifest" => Ok(Self::Manifest),
            "manifest+block-table" => Ok(Self::ManifestAndBlockTable),
            "per-file" => Ok(Self::PerFileExperimental),
            other => Err(QsrlError::Parse(format!(
                "unsupported signature scope '{other}'"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestEncoding {
    TextV1,
    BinaryV1,
}

impl ManifestEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TextV1 => "text-v1",
            Self::BinaryV1 => "binary-v1",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::TextV1 => 1,
            Self::BinaryV1 => 2,
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::TextV1),
            2 => Ok(Self::BinaryV1),
            other => Err(QsrlError::Parse(format!(
                "unsupported manifest encoding code {other}"
            ))),
        }
    }
}

impl FromStr for ManifestEncoding {
    type Err = QsrlError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "text-v1" => Ok(Self::TextV1),
            "binary-v1" => Ok(Self::BinaryV1),
            other => Err(QsrlError::Parse(format!(
                "unsupported manifest encoding '{other}'"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionMode {
    None,
    Rle,
}

impl CompressionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Rle => "rle",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Rle => 1,
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::None),
            1 => Ok(Self::Rle),
            other => Err(QsrlError::Parse(format!(
                "unsupported compression mode code {other}"
            ))),
        }
    }
}

impl FromStr for CompressionMode {
    type Err = QsrlError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "rle" => Ok(Self::Rle),
            other => Err(QsrlError::Parse(format!(
                "unsupported compression mode '{other}'"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionLayout {
    PerFile,
    WholeArchive,
}

impl CompressionLayout {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PerFile => "per-file",
            Self::WholeArchive => "whole-archive",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::PerFile => 1,
            Self::WholeArchive => 2,
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::PerFile),
            2 => Ok(Self::WholeArchive),
            other => Err(QsrlError::Parse(format!(
                "unsupported compression layout code {other}"
            ))),
        }
    }
}

impl FromStr for CompressionLayout {
    type Err = QsrlError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "per-file" => Ok(Self::PerFile),
            "whole-archive" => Ok(Self::WholeArchive),
            other => Err(QsrlError::Parse(format!(
                "unsupported compression layout '{other}'"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KemAlgorithm {
    MlKem,
}

impl KemAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKem => "ml-kem",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::MlKem => 1,
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::MlKem),
            other => Err(QsrlError::UnsupportedAlgorithm(format!(
                "unsupported KEM algorithm code {other}"
            ))),
        }
    }
}

impl FromStr for KemAlgorithm {
    type Err = QsrlError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "ml-kem" => Ok(Self::MlKem),
            other => Err(QsrlError::UnsupportedAlgorithm(format!(
                "unsupported KEM algorithm '{other}'"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadAlgorithm {
    Aes256Gcm,
}

impl AeadAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Aes256Gcm => 1,
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Aes256Gcm),
            other => Err(QsrlError::UnsupportedAlgorithm(format!(
                "unsupported AEAD algorithm code {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub compression: CompressionMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub format_version: u16,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature_placement: SignaturePlacement,
    pub signature_scope: SignatureScope,
    pub manifest_encoding: ManifestEncoding,
    pub compression_mode: CompressionMode,
    pub compression_layout: CompressionLayout,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        match self.manifest_encoding {
            ManifestEncoding::TextV1 => Ok(self.serialize_text_v1().into_bytes()),
            ManifestEncoding::BinaryV1 => self.serialize_binary_v1(),
        }
    }

    pub fn deserialize(bytes: &[u8], encoding: ManifestEncoding) -> Result<Self> {
        match encoding {
            ManifestEncoding::TextV1 => Self::deserialize_text_v1(bytes),
            ManifestEncoding::BinaryV1 => Self::deserialize_binary_v1(bytes),
        }
    }

    fn serialize_text_v1(&self) -> String {
        let mut output = String::new();
        output.push_str("qsrl-manifest-v1\n");
        output.push_str(&format!("format-version={}\n", self.format_version));
        output.push_str(&format!(
            "signature-algorithm={}\n",
            self.signature_algorithm.as_str()
        ));
        output.push_str(&format!(
            "signature-placement={}\n",
            self.signature_placement.as_str()
        ));
        output.push_str(&format!(
            "signature-scope={}\n",
            self.signature_scope.as_str()
        ));
        output.push_str(&format!(
            "manifest-encoding={}\n",
            self.manifest_encoding.as_str()
        ));
        output.push_str(&format!(
            "compression-mode={}\n",
            self.compression_mode.as_str()
        ));
        output.push_str(&format!(
            "compression-layout={}\n",
            self.compression_layout.as_str()
        ));
        output.push_str("path-normalization=forward-slash\n");
        output.push_str("timestamps=omitted\n");
        output.push_str(&format!("file-count={}\n", self.files.len()));
        for (index, entry) in self.files.iter().enumerate() {
            output.push_str(&format!("file.{index}.path={}\n", entry.path));
            output.push_str(&format!("file.{index}.size={}\n", entry.size));
            output.push_str(&format!(
                "file.{index}.sha256={}\n",
                hex_encode(&entry.sha256)
            ));
            output.push_str(&format!(
                "file.{index}.compression={}\n",
                entry.compression.as_str()
            ));
        }
        output
    }

    fn deserialize_text_v1(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| QsrlError::InvalidFormat("manifest text is not valid UTF-8".into()))?;
        let mut lines = text.lines();
        if lines.next() != Some("qsrl-manifest-v1") {
            return Err(QsrlError::InvalidFormat(
                "manifest text header must start with qsrl-manifest-v1".into(),
            ));
        }
        let body_lines: Vec<&str> = lines.collect();

        #[derive(Default)]
        struct PartialFileEntry {
            path: Option<String>,
            size: Option<u64>,
            sha256: Option<[u8; 32]>,
            compression: Option<CompressionMode>,
        }

        let mut format_version = None;
        let mut signature_algorithm = None;
        let mut signature_placement = None;
        let mut signature_scope = None;
        let mut manifest_encoding = None;
        let mut compression_mode = None;
        let mut compression_layout = None;
        let mut file_count = None;

        for line in &body_lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                QsrlError::InvalidFormat(format!("invalid manifest line '{line}'"))
            })?;
            if key == "file-count" {
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| QsrlError::Parse("invalid file count".into()))?;
                if file_count.replace(parsed).is_some() {
                    return Err(QsrlError::InvalidFormat(
                        "manifest file-count is duplicated".into(),
                    ));
                }
            }
        }
        let expected_count = file_count
            .ok_or_else(|| QsrlError::InvalidFormat("manifest file-count is missing".into()))?;
        validate_record_count(expected_count, MAX_MANIFEST_FILES, "manifest file count")?;
        let mut files: Vec<PartialFileEntry> = (0..expected_count)
            .map(|_| PartialFileEntry::default())
            .collect();

        for line in body_lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                QsrlError::InvalidFormat(format!("invalid manifest line '{line}'"))
            })?;

            match key {
                "format-version" => {
                    format_version =
                        Some(value.parse::<u16>().map_err(|_| {
                            QsrlError::Parse("invalid manifest format version".into())
                        })?)
                }
                "signature-algorithm" => signature_algorithm = Some(value.parse()?),
                "signature-placement" => signature_placement = Some(value.parse()?),
                "signature-scope" => signature_scope = Some(value.parse()?),
                "manifest-encoding" => manifest_encoding = Some(value.parse()?),
                "compression-mode" => compression_mode = Some(value.parse()?),
                "compression-layout" => compression_layout = Some(value.parse()?),
                "file-count" => {}
                "path-normalization" | "timestamps" => {}
                _ if key.starts_with("file.") => {
                    let rest = key
                        .strip_prefix("file.")
                        .ok_or_else(|| QsrlError::InvalidFormat("invalid file record".into()))?;
                    let (index_text, field) = rest.split_once('.').ok_or_else(|| {
                        QsrlError::InvalidFormat(format!("invalid file record '{key}'"))
                    })?;
                    let index = index_text
                        .parse::<usize>()
                        .map_err(|_| QsrlError::Parse("invalid file index".into()))?;
                    if index >= expected_count {
                        return Err(QsrlError::InvalidFormat(format!(
                            "manifest file index {index} is outside declared file-count {expected_count}"
                        )));
                    }
                    let entry = &mut files[index];
                    match field {
                        "path" => entry.path = Some(value.to_string()),
                        "size" => {
                            entry.size = Some(
                                value
                                    .parse::<u64>()
                                    .map_err(|_| QsrlError::Parse("invalid file size".into()))?,
                            )
                        }
                        "sha256" => {
                            let decoded = hex_decode(value)?;
                            if decoded.len() != 32 {
                                return Err(QsrlError::InvalidFormat(
                                    "manifest sha256 value must be 32 bytes".into(),
                                ));
                            }
                            let mut digest = [0u8; 32];
                            digest.copy_from_slice(&decoded);
                            entry.sha256 = Some(digest);
                        }
                        "compression" => entry.compression = Some(value.parse()?),
                        _ => {
                            return Err(QsrlError::InvalidFormat(format!(
                                "unknown manifest file field '{field}'"
                            )));
                        }
                    }
                }
                other => {
                    return Err(QsrlError::InvalidFormat(format!(
                        "unknown manifest key '{other}'"
                    )));
                }
            }
        }

        let files = files
            .into_iter()
            .map(|entry| {
                Ok(FileEntry {
                    path: entry.path.ok_or_else(|| {
                        QsrlError::InvalidFormat("manifest file path missing".into())
                    })?,
                    size: entry.size.ok_or_else(|| {
                        QsrlError::InvalidFormat("manifest file size missing".into())
                    })?,
                    sha256: entry.sha256.ok_or_else(|| {
                        QsrlError::InvalidFormat("manifest file sha256 missing".into())
                    })?,
                    compression: entry.compression.unwrap_or(CompressionMode::None),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let manifest = Self {
            format_version: format_version.ok_or_else(|| {
                QsrlError::InvalidFormat("manifest format-version missing".into())
            })?,
            signature_algorithm: signature_algorithm.ok_or_else(|| {
                QsrlError::InvalidFormat("manifest signature-algorithm missing".into())
            })?,
            signature_placement: signature_placement.ok_or_else(|| {
                QsrlError::InvalidFormat("manifest signature-placement missing".into())
            })?,
            signature_scope: signature_scope.ok_or_else(|| {
                QsrlError::InvalidFormat("manifest signature-scope missing".into())
            })?,
            manifest_encoding: manifest_encoding.ok_or_else(|| {
                QsrlError::InvalidFormat("manifest manifest-encoding missing".into())
            })?,
            compression_mode: compression_mode.ok_or_else(|| {
                QsrlError::InvalidFormat("manifest compression-mode missing".into())
            })?,
            compression_layout: compression_layout.ok_or_else(|| {
                QsrlError::InvalidFormat("manifest compression-layout missing".into())
            })?,
            files,
        };

        if manifest.format_version != FORMAT_VERSION {
            return Err(QsrlError::UnsupportedVersion(manifest.format_version));
        }
        Ok(manifest)
    }

    fn serialize_binary_v1(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        output.extend_from_slice(MANIFEST_BINARY_MAGIC);
        push_u16_le(&mut output, 1);
        push_u16_le(&mut output, self.format_version);
        output.push(self.signature_algorithm.code());
        output.push(self.signature_placement.code());
        output.push(self.signature_scope.code());
        output.push(self.manifest_encoding.code());
        output.push(self.compression_mode.code());
        output.push(self.compression_layout.code());
        push_u32_le(&mut output, self.files.len() as u32);
        for entry in &self.files {
            let path_bytes = entry.path.as_bytes();
            if path_bytes.len() > u16::MAX as usize {
                return Err(QsrlError::UnsupportedFeature(format!(
                    "path is too long for prototype manifest: {}",
                    entry.path
                )));
            }
            push_u16_le(&mut output, path_bytes.len() as u16);
            output.extend_from_slice(path_bytes);
            push_u64_le(&mut output, entry.size);
            output.extend_from_slice(&entry.sha256);
            output.push(entry.compression.code());
        }
        Ok(output)
    }

    fn deserialize_binary_v1(bytes: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        if take_bytes(bytes, &mut cursor, 4, "manifest magic")? != MANIFEST_BINARY_MAGIC {
            return Err(QsrlError::InvalidFormat(
                "binary manifest magic is not QMAN".into(),
            ));
        }
        let manifest_version = read_u16_le(bytes, &mut cursor, "manifest schema version")?;
        if manifest_version != 1 {
            return Err(QsrlError::UnsupportedVersion(manifest_version));
        }
        let format_version = read_u16_le(bytes, &mut cursor, "manifest format version")?;
        if format_version != FORMAT_VERSION {
            return Err(QsrlError::UnsupportedVersion(format_version));
        }
        let signature_algorithm = SignatureAlgorithm::from_code(
            *take_bytes(bytes, &mut cursor, 1, "signature algorithm")?
                .first()
                .expect("one byte"),
        )?;
        let signature_placement = SignaturePlacement::from_code(
            *take_bytes(bytes, &mut cursor, 1, "signature placement")?
                .first()
                .expect("one byte"),
        )?;
        let signature_scope = SignatureScope::from_code(
            *take_bytes(bytes, &mut cursor, 1, "signature scope")?
                .first()
                .expect("one byte"),
        )?;
        let manifest_encoding = ManifestEncoding::from_code(
            *take_bytes(bytes, &mut cursor, 1, "manifest encoding")?
                .first()
                .expect("one byte"),
        )?;
        let compression_mode = CompressionMode::from_code(
            *take_bytes(bytes, &mut cursor, 1, "compression mode")?
                .first()
                .expect("one byte"),
        )?;
        let compression_layout = CompressionLayout::from_code(
            *take_bytes(bytes, &mut cursor, 1, "compression layout")?
                .first()
                .expect("one byte"),
        )?;
        let file_count = read_u32_le(bytes, &mut cursor, "file count")? as usize;
        validate_record_count(file_count, MAX_MANIFEST_FILES, "manifest file count")?;
        if bytes.len() < BINARY_MANIFEST_PREFIX_LEN {
            return Err(QsrlError::InvalidFormat(
                "binary manifest is shorter than its fixed prefix".into(),
            ));
        }
        let max_possible =
            bytes.len().saturating_sub(BINARY_MANIFEST_PREFIX_LEN) / MIN_BINARY_FILE_ENTRY_LEN;
        if file_count > max_possible {
            return Err(QsrlError::InvalidFormat(format!(
                "binary manifest declared {file_count} files but section length can hold at most {max_possible}"
            )));
        }
        let mut files = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            let path_len = read_u16_le(bytes, &mut cursor, "file path length")? as usize;
            let path =
                String::from_utf8(take_bytes(bytes, &mut cursor, path_len, "file path")?.to_vec())
                    .map_err(|_| QsrlError::InvalidFormat("file path is not valid UTF-8".into()))?;
            let size = read_u64_le(bytes, &mut cursor, "file size")?;
            let digest_bytes = take_bytes(bytes, &mut cursor, 32, "file sha256")?;
            let mut digest = [0u8; 32];
            digest.copy_from_slice(digest_bytes);
            let compression = CompressionMode::from_code(
                *take_bytes(bytes, &mut cursor, 1, "file compression")?
                    .first()
                    .expect("one byte"),
            )?;
            files.push(FileEntry {
                path,
                size,
                sha256: digest,
                compression,
            });
        }
        if cursor != bytes.len() {
            return Err(QsrlError::InvalidFormat(
                "binary manifest has trailing bytes".into(),
            ));
        }

        Ok(Self {
            format_version,
            signature_algorithm,
            signature_placement,
            signature_scope,
            manifest_encoding,
            compression_mode,
            compression_layout,
            files,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockEntry {
    pub stored_offset: u64,
    pub stored_len: u64,
    pub raw_offset: u64,
    pub raw_len: u64,
    pub compression: CompressionMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockTable {
    pub entries: Vec<BlockEntry>,
}

impl BlockTable {
    pub fn serialize(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(BLOCK_TABLE_MAGIC);
        push_u16_le(&mut output, 1);
        push_u32_le(&mut output, self.entries.len() as u32);
        for entry in &self.entries {
            push_u64_le(&mut output, entry.stored_offset);
            push_u64_le(&mut output, entry.stored_len);
            push_u64_le(&mut output, entry.raw_offset);
            push_u64_le(&mut output, entry.raw_len);
            output.push(entry.compression.code());
            output.extend_from_slice(&[0u8; 7]);
        }
        output
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        if take_bytes(bytes, &mut cursor, 4, "block table magic")? != BLOCK_TABLE_MAGIC {
            return Err(QsrlError::InvalidFormat(
                "block table magic is not QBLK".into(),
            ));
        }
        let version = read_u16_le(bytes, &mut cursor, "block table version")?;
        if version != 1 {
            return Err(QsrlError::UnsupportedVersion(version));
        }
        let count = read_u32_le(bytes, &mut cursor, "block entry count")? as usize;
        validate_record_count(count, MAX_BLOCK_ENTRIES, "block entry count")?;
        if bytes.len() < BLOCK_TABLE_PREFIX_LEN {
            return Err(QsrlError::InvalidFormat(
                "block table is shorter than its fixed prefix".into(),
            ));
        }
        let remaining = bytes.len().saturating_sub(BLOCK_TABLE_PREFIX_LEN);
        if remaining != count.saturating_mul(BLOCK_ENTRY_LEN) {
            return Err(QsrlError::InvalidFormat(format!(
                "block table declared {count} entries but section length is inconsistent"
            )));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let stored_offset = read_u64_le(bytes, &mut cursor, "stored offset")?;
            let stored_len = read_u64_le(bytes, &mut cursor, "stored length")?;
            let raw_offset = read_u64_le(bytes, &mut cursor, "raw offset")?;
            let raw_len = read_u64_le(bytes, &mut cursor, "raw length")?;
            let compression = CompressionMode::from_code(
                *take_bytes(bytes, &mut cursor, 1, "block compression")?
                    .first()
                    .expect("one byte"),
            )?;
            let _reserved = take_bytes(bytes, &mut cursor, 7, "block table padding")?;
            entries.push(BlockEntry {
                stored_offset,
                stored_len,
                raw_offset,
                raw_len,
                compression,
            });
        }
        if cursor != bytes.len() {
            return Err(QsrlError::InvalidFormat(
                "block table has trailing bytes".into(),
            ));
        }
        Ok(Self { entries })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveHeader {
    pub format_version: u16,
    pub manifest_encoding: ManifestEncoding,
    pub signature_placement: SignaturePlacement,
    pub signature_scope: SignatureScope,
    pub compression_mode: CompressionMode,
    pub compression_layout: CompressionLayout,
    pub flags: u8,
    pub manifest_len: u64,
    pub block_table_len: u64,
    pub payload_len: u64,
    pub signature_len: u64,
    pub recipient_records_len: u64,
}

impl ArchiveHeader {
    pub const SIZE: usize = 64;

    pub fn serialize(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(Self::SIZE);
        output.extend_from_slice(ARCHIVE_MAGIC);
        push_u16_le(&mut output, 1);
        push_u16_le(&mut output, self.format_version);
        output.push(self.manifest_encoding.code());
        output.push(self.signature_placement.code());
        output.push(self.signature_scope.code());
        output.push(self.compression_mode.code());
        output.push(self.compression_layout.code());
        output.push(self.flags);
        push_u64_le(&mut output, self.manifest_len);
        push_u64_le(&mut output, self.block_table_len);
        push_u64_le(&mut output, self.payload_len);
        push_u64_le(&mut output, self.signature_len);
        push_u64_le(&mut output, self.recipient_records_len);
        output.extend_from_slice(&[0u8; 10]);
        output
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(QsrlError::InvalidFormat(
                "archive is smaller than the fixed QSRL header".into(),
            ));
        }

        let mut cursor = 0usize;
        if take_bytes(bytes, &mut cursor, 4, "archive magic")? != ARCHIVE_MAGIC {
            return Err(QsrlError::InvalidFormat("archive magic is not QSRL".into()));
        }
        let header_version = read_u16_le(bytes, &mut cursor, "header version")?;
        if header_version != 1 {
            return Err(QsrlError::UnsupportedVersion(header_version));
        }
        let format_version = read_u16_le(bytes, &mut cursor, "format version")?;
        if format_version != FORMAT_VERSION {
            return Err(QsrlError::UnsupportedVersion(format_version));
        }
        let manifest_encoding = ManifestEncoding::from_code(
            *take_bytes(bytes, &mut cursor, 1, "manifest encoding")?
                .first()
                .expect("one byte"),
        )?;
        let signature_placement = SignaturePlacement::from_code(
            *take_bytes(bytes, &mut cursor, 1, "signature placement")?
                .first()
                .expect("one byte"),
        )?;
        let signature_scope = SignatureScope::from_code(
            *take_bytes(bytes, &mut cursor, 1, "signature scope")?
                .first()
                .expect("one byte"),
        )?;
        let compression_mode = CompressionMode::from_code(
            *take_bytes(bytes, &mut cursor, 1, "compression mode")?
                .first()
                .expect("one byte"),
        )?;
        let compression_layout = CompressionLayout::from_code(
            *take_bytes(bytes, &mut cursor, 1, "compression layout")?
                .first()
                .expect("one byte"),
        )?;
        let flags = *take_bytes(bytes, &mut cursor, 1, "archive flags")?
            .first()
            .expect("one byte");
        let manifest_len = read_u64_le(bytes, &mut cursor, "manifest length")?;
        let block_table_len = read_u64_le(bytes, &mut cursor, "block table length")?;
        let payload_len = read_u64_le(bytes, &mut cursor, "payload length")?;
        let signature_len = read_u64_le(bytes, &mut cursor, "signature length")?;
        let recipient_records_len = read_u64_le(bytes, &mut cursor, "recipient records length")?;
        let _reserved = take_bytes(bytes, &mut cursor, 10, "header padding")?;

        Ok(Self {
            format_version,
            manifest_encoding,
            signature_placement,
            signature_scope,
            compression_mode,
            compression_layout,
            flags,
            manifest_len,
            block_table_len,
            payload_len,
            signature_len,
            recipient_records_len,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureRecord {
    pub algorithm: SignatureAlgorithm,
    pub scope: SignatureScope,
    pub implementation: u8,
    pub public_key_fingerprint: [u8; 32],
    pub signed_payload_digest: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientRecord {
    pub implementation: u8,
    pub public_key_fingerprint: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub wrap_nonce: Vec<u8>,
    pub wrapped_key: Vec<u8>,
    pub wrap_tag: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptionSection {
    pub kem_algorithm: KemAlgorithm,
    pub kem_method_name: String,
    pub aead_algorithm: AeadAlgorithm,
    pub payload_nonce: Vec<u8>,
    pub payload_tag: Vec<u8>,
    pub recipients: Vec<RecipientRecord>,
}

impl EncryptionSection {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut output = self.aad_bytes()?;
        output.extend_from_slice(&self.payload_tag);
        Ok(output)
    }

    pub fn aad_bytes(&self) -> Result<Vec<u8>> {
        let method_name = self.kem_method_name.as_bytes();
        if method_name.len() > u16::MAX as usize {
            return Err(QsrlError::UnsupportedFeature(
                "KEM method name is too long for prototype encoding".into(),
            ));
        }
        if self.recipients.len() > u32::MAX as usize {
            return Err(QsrlError::UnsupportedFeature(
                "too many recipient records for prototype encoding".into(),
            ));
        }
        if self.payload_nonce.len() > u8::MAX as usize || self.payload_tag.len() > u8::MAX as usize
        {
            return Err(QsrlError::UnsupportedFeature(
                "AEAD nonce or tag is too long for prototype encoding".into(),
            ));
        }

        let mut output = Vec::new();
        output.extend_from_slice(ENCRYPTION_MAGIC);
        push_u16_le(&mut output, 1);
        output.push(self.kem_algorithm.code());
        output.push(self.aead_algorithm.code());
        output.push(self.payload_nonce.len() as u8);
        output.push(self.payload_tag.len() as u8);
        push_u32_le(&mut output, self.recipients.len() as u32);
        push_u16_le(&mut output, method_name.len() as u16);
        output.extend_from_slice(&[0u8; 2]);
        output.extend_from_slice(method_name);
        output.extend_from_slice(&self.payload_nonce);
        for recipient in &self.recipients {
            if recipient.kem_ciphertext.len() > u32::MAX as usize
                || recipient.wrapped_key.len() > u32::MAX as usize
                || recipient.wrap_nonce.len() > u8::MAX as usize
                || recipient.wrap_tag.len() > u8::MAX as usize
            {
                return Err(QsrlError::UnsupportedFeature(
                    "recipient record is too large for prototype encoding".into(),
                ));
            }
            output.push(recipient.implementation);
            output.push(recipient.wrap_nonce.len() as u8);
            output.push(recipient.wrap_tag.len() as u8);
            output.push(0);
            output.extend_from_slice(&recipient.public_key_fingerprint);
            push_u32_le(&mut output, recipient.kem_ciphertext.len() as u32);
            push_u32_le(&mut output, recipient.wrapped_key.len() as u32);
            output.extend_from_slice(&recipient.kem_ciphertext);
            output.extend_from_slice(&recipient.wrap_nonce);
            output.extend_from_slice(&recipient.wrapped_key);
            output.extend_from_slice(&recipient.wrap_tag);
        }
        Ok(output)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        if take_bytes(bytes, &mut cursor, 4, "encryption magic")? != ENCRYPTION_MAGIC {
            return Err(QsrlError::InvalidFormat(
                "encryption section magic is not QENC".into(),
            ));
        }
        let version = read_u16_le(bytes, &mut cursor, "encryption section version")?;
        if version != 1 {
            return Err(QsrlError::UnsupportedVersion(version));
        }
        let kem_algorithm = KemAlgorithm::from_code(
            *take_bytes(bytes, &mut cursor, 1, "KEM algorithm")?
                .first()
                .expect("one byte"),
        )?;
        let aead_algorithm = AeadAlgorithm::from_code(
            *take_bytes(bytes, &mut cursor, 1, "AEAD algorithm")?
                .first()
                .expect("one byte"),
        )?;
        let payload_nonce_len = *take_bytes(bytes, &mut cursor, 1, "payload nonce length")?
            .first()
            .expect("one byte") as usize;
        let payload_tag_len = *take_bytes(bytes, &mut cursor, 1, "payload tag length")?
            .first()
            .expect("one byte") as usize;
        let recipient_count = read_u32_le(bytes, &mut cursor, "recipient count")? as usize;
        validate_record_count(
            recipient_count,
            MAX_RECIPIENT_RECORDS,
            "recipient record count",
        )?;
        let method_name_len = read_u16_le(bytes, &mut cursor, "KEM method name length")? as usize;
        let _reserved = take_bytes(bytes, &mut cursor, 2, "encryption section padding")?;
        let kem_method_name = String::from_utf8(
            take_bytes(bytes, &mut cursor, method_name_len, "KEM method name")?.to_vec(),
        )
        .map_err(|_| QsrlError::InvalidFormat("KEM method name is not valid UTF-8".into()))?;
        let payload_nonce =
            take_bytes(bytes, &mut cursor, payload_nonce_len, "payload nonce")?.to_vec();
        let remaining = bytes.len().saturating_sub(cursor);
        if remaining < payload_tag_len {
            return Err(QsrlError::InvalidFormat(
                "encryption section is too short for payload tag".into(),
            ));
        }
        let max_possible_recipients =
            remaining.saturating_sub(payload_tag_len) / MIN_RECIPIENT_RECORD_LEN;
        if recipient_count > max_possible_recipients {
            return Err(QsrlError::InvalidFormat(format!(
                "encryption section declared {recipient_count} recipients but section length can hold at most {max_possible_recipients}"
            )));
        }

        let mut recipients = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            let implementation = *take_bytes(bytes, &mut cursor, 1, "recipient implementation")?
                .first()
                .expect("one byte");
            let wrap_nonce_len = *take_bytes(bytes, &mut cursor, 1, "recipient wrap nonce length")?
                .first()
                .expect("one byte") as usize;
            let wrap_tag_len = *take_bytes(bytes, &mut cursor, 1, "recipient wrap tag length")?
                .first()
                .expect("one byte") as usize;
            let _record_reserved = take_bytes(bytes, &mut cursor, 1, "recipient record padding")?;
            let mut public_key_fingerprint = [0u8; 32];
            public_key_fingerprint.copy_from_slice(take_bytes(
                bytes,
                &mut cursor,
                32,
                "recipient public key fingerprint",
            )?);
            let kem_ciphertext_len =
                read_u32_le(bytes, &mut cursor, "recipient KEM ciphertext length")? as usize;
            let wrapped_key_len =
                read_u32_le(bytes, &mut cursor, "recipient wrapped key length")? as usize;
            let kem_ciphertext = take_bytes(
                bytes,
                &mut cursor,
                kem_ciphertext_len,
                "recipient KEM ciphertext",
            )?
            .to_vec();
            let wrap_nonce =
                take_bytes(bytes, &mut cursor, wrap_nonce_len, "recipient wrap nonce")?.to_vec();
            let wrapped_key =
                take_bytes(bytes, &mut cursor, wrapped_key_len, "recipient wrapped key")?.to_vec();
            let wrap_tag =
                take_bytes(bytes, &mut cursor, wrap_tag_len, "recipient wrap tag")?.to_vec();
            recipients.push(RecipientRecord {
                implementation,
                public_key_fingerprint,
                kem_ciphertext,
                wrap_nonce,
                wrapped_key,
                wrap_tag,
            });
        }

        let payload_tag =
            take_bytes(bytes, &mut cursor, payload_tag_len, "payload AEAD tag")?.to_vec();
        if cursor != bytes.len() {
            return Err(QsrlError::InvalidFormat(
                "encryption section has trailing bytes".into(),
            ));
        }

        Ok(Self {
            kem_algorithm,
            kem_method_name,
            aead_algorithm,
            payload_nonce,
            payload_tag,
            recipients,
        })
    }
}

impl SignatureRecord {
    pub fn serialize(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(SIGNATURE_MAGIC);
        push_u16_le(&mut output, 1);
        output.push(self.algorithm.code());
        output.push(self.scope.code());
        output.push(self.implementation);
        output.extend_from_slice(&[0u8; 3]);
        output.extend_from_slice(&self.public_key_fingerprint);
        output.extend_from_slice(&self.signed_payload_digest);
        push_u32_le(&mut output, self.signature.len() as u32);
        output.extend_from_slice(&self.signature);
        output
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut cursor = 0usize;
        if take_bytes(bytes, &mut cursor, 4, "signature magic")? != SIGNATURE_MAGIC {
            return Err(QsrlError::InvalidFormat(
                "signature record magic is not QSIG".into(),
            ));
        }
        let version = read_u16_le(bytes, &mut cursor, "signature version")?;
        if version != 1 {
            return Err(QsrlError::UnsupportedVersion(version));
        }
        let algorithm = SignatureAlgorithm::from_code(
            *take_bytes(bytes, &mut cursor, 1, "signature algorithm")?
                .first()
                .expect("one byte"),
        )?;
        let scope = SignatureScope::from_code(
            *take_bytes(bytes, &mut cursor, 1, "signature scope")?
                .first()
                .expect("one byte"),
        )?;
        let implementation = *take_bytes(bytes, &mut cursor, 1, "signature implementation")?
            .first()
            .expect("one byte");
        let _reserved = take_bytes(bytes, &mut cursor, 3, "signature padding")?;
        let mut public_key_fingerprint = [0u8; 32];
        public_key_fingerprint.copy_from_slice(take_bytes(
            bytes,
            &mut cursor,
            32,
            "public key fingerprint",
        )?);
        let mut signed_payload_digest = [0u8; 32];
        signed_payload_digest.copy_from_slice(take_bytes(
            bytes,
            &mut cursor,
            32,
            "signed payload digest",
        )?);
        let signature_len = read_u32_le(bytes, &mut cursor, "signature length")? as usize;
        let signature = take_bytes(bytes, &mut cursor, signature_len, "signature bytes")?.to_vec();
        if cursor != bytes.len() {
            return Err(QsrlError::InvalidFormat(
                "signature record has trailing bytes".into(),
            ));
        }
        Ok(Self {
            algorithm,
            scope,
            implementation,
            public_key_fingerprint,
            signed_payload_digest,
            signature,
        })
    }
}

fn validate_record_count(count: usize, max: usize, label: &str) -> Result<()> {
    if count > max {
        return Err(QsrlError::InvalidFormat(format!(
            "{label} {count} exceeds prototype cap {max}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AeadAlgorithm, CompressionLayout, CompressionMode, EncryptionSection, FileEntry,
        KemAlgorithm, Manifest, ManifestEncoding, SignatureAlgorithm, SignaturePlacement,
        SignatureScope,
    };

    #[test]
    fn text_manifest_round_trip() {
        let manifest = Manifest {
            format_version: 1,
            signature_algorithm: SignatureAlgorithm::MlDsa,
            signature_placement: SignaturePlacement::Embedded,
            signature_scope: SignatureScope::Manifest,
            manifest_encoding: ManifestEncoding::TextV1,
            compression_mode: CompressionMode::None,
            compression_layout: CompressionLayout::PerFile,
            files: vec![FileEntry {
                path: "alpha.txt".into(),
                size: 3,
                sha256: [1u8; 32],
                compression: CompressionMode::None,
            }],
        };
        let bytes = manifest.serialize().expect("serialize");
        let decoded = Manifest::deserialize(&bytes, ManifestEncoding::TextV1).expect("deserialize");
        assert_eq!(manifest, decoded);
    }

    #[test]
    fn encryption_section_rejects_huge_recipient_count() {
        let section = EncryptionSection {
            kem_algorithm: KemAlgorithm::MlKem,
            kem_method_name: "ML-KEM-768".into(),
            aead_algorithm: AeadAlgorithm::Aes256Gcm,
            payload_nonce: vec![0u8; 12],
            payload_tag: vec![0u8; 16],
            recipients: Vec::new(),
        };
        let mut bytes = section.serialize().expect("serialize encryption section");
        bytes[10..14].copy_from_slice(&u32::MAX.to_le_bytes());

        let error = EncryptionSection::deserialize(&bytes).expect_err("huge count should fail");
        assert!(matches!(error, crate::error::QsrlError::InvalidFormat(_)));
    }
}
