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

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "ml-dsa" => Ok(Self::MlDsa),
            "slh-dsa" => Ok(Self::SlhDsa),
            other => Err(QsrlError::UnsupportedAlgorithm(format!(
                "unsupported signature algorithm '{other}'"
            ))),
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

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "embedded" => Ok(Self::Embedded),
            "detached" => Ok(Self::Detached),
            other => Err(QsrlError::Parse(format!(
                "unsupported signature placement '{other}'"
            ))),
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

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "manifest" => Ok(Self::Manifest),
            "manifest+block-table" => Ok(Self::ManifestAndBlockTable),
            "per-file" => Ok(Self::PerFileExperimental),
            other => Err(QsrlError::Parse(format!(
                "unsupported signature scope '{other}'"
            ))),
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

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "text-v1" => Ok(Self::TextV1),
            "binary-v1" => Ok(Self::BinaryV1),
            other => Err(QsrlError::Parse(format!(
                "unsupported manifest encoding '{other}'"
            ))),
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

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "none" => Ok(Self::None),
            "rle" => Ok(Self::Rle),
            other => Err(QsrlError::Parse(format!(
                "unsupported compression mode '{other}'"
            ))),
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

    pub fn from_str(value: &str) -> Result<Self> {
        match value {
            "per-file" => Ok(Self::PerFile),
            "whole-archive" => Ok(Self::WholeArchive),
            other => Err(QsrlError::Parse(format!(
                "unsupported compression layout '{other}'"
            ))),
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
        let mut files: Vec<PartialFileEntry> = Vec::new();

        for line in lines {
            if line.trim().is_empty() {
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
                "signature-algorithm" => {
                    signature_algorithm = Some(SignatureAlgorithm::from_str(value)?)
                }
                "signature-placement" => {
                    signature_placement = Some(SignaturePlacement::from_str(value)?)
                }
                "signature-scope" => signature_scope = Some(SignatureScope::from_str(value)?),
                "manifest-encoding" => manifest_encoding = Some(ManifestEncoding::from_str(value)?),
                "compression-mode" => compression_mode = Some(CompressionMode::from_str(value)?),
                "compression-layout" => {
                    compression_layout = Some(CompressionLayout::from_str(value)?)
                }
                "file-count" => {
                    file_count = Some(
                        value
                            .parse::<usize>()
                            .map_err(|_| QsrlError::Parse("invalid file count".into()))?,
                    )
                }
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
                    if files.len() <= index {
                        files.resize_with(index + 1, PartialFileEntry::default);
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
                        "compression" => {
                            entry.compression = Some(CompressionMode::from_str(value)?)
                        }
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

        let expected_count = file_count
            .ok_or_else(|| QsrlError::InvalidFormat("manifest file-count is missing".into()))?;
        if files.len() != expected_count {
            return Err(QsrlError::InvalidFormat(format!(
                "manifest declared {expected_count} files but encoded {}",
                files.len()
            )));
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

#[cfg(test)]
mod tests {
    use super::{
        CompressionLayout, CompressionMode, FileEntry, Manifest, ManifestEncoding,
        SignatureAlgorithm, SignaturePlacement, SignatureScope,
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
}
