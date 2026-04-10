use std::path::{Path, PathBuf};

use crate::FORMAT_VERSION;
use crate::codec::{compress, decompress};
use crate::error::{QsrlError, Result};
use crate::protocol::{
    ArchiveHeader, BlockEntry, BlockTable, CompressionLayout, FileEntry, Manifest,
    ManifestEncoding, SignatureAlgorithm, SignaturePlacement, SignatureRecord, SignatureScope,
};
use crate::sha256::digest;
use crate::util::{collect_input_files, read_bytes, write_bytes};

#[derive(Clone, Debug)]
pub struct PackPlan {
    pub format_version: u16,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature_placement: SignaturePlacement,
    pub signature_scope: SignatureScope,
    pub manifest_encoding: ManifestEncoding,
    pub compression_mode: crate::protocol::CompressionMode,
    pub compression_layout: CompressionLayout,
}

#[derive(Clone, Debug)]
pub struct Archive {
    pub header: ArchiveHeader,
    pub manifest: Manifest,
    pub manifest_bytes: Vec<u8>,
    pub block_table: BlockTable,
    pub block_table_bytes: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Option<SignatureRecord>,
}

impl Archive {
    pub fn build_from_path(input_path: &Path, plan: &PackPlan) -> Result<Self> {
        if plan.format_version != FORMAT_VERSION {
            return Err(QsrlError::UnsupportedVersion(plan.format_version));
        }

        let input_files = collect_input_files(input_path)?;
        let mut manifest_files = Vec::with_capacity(input_files.len());
        let mut block_entries = Vec::with_capacity(input_files.len());
        let mut payload = Vec::new();
        let mut raw_offset = 0u64;

        match plan.compression_layout {
            CompressionLayout::PerFile => {
                for input in &input_files {
                    let digest = digest(&input.data);
                    let stored = compress(plan.compression_mode, &input.data);
                    let stored_offset = payload.len() as u64;
                    payload.extend_from_slice(&stored);
                    manifest_files.push(FileEntry {
                        path: input.path.clone(),
                        size: input.data.len() as u64,
                        sha256: digest,
                        compression: plan.compression_mode,
                    });
                    block_entries.push(BlockEntry {
                        stored_offset,
                        stored_len: stored.len() as u64,
                        raw_offset,
                        raw_len: input.data.len() as u64,
                        compression: plan.compression_mode,
                    });
                    raw_offset += input.data.len() as u64;
                }
            }
            CompressionLayout::WholeArchive => {
                let mut raw_payload = Vec::new();
                for input in &input_files {
                    let digest = digest(&input.data);
                    manifest_files.push(FileEntry {
                        path: input.path.clone(),
                        size: input.data.len() as u64,
                        sha256: digest,
                        compression: plan.compression_mode,
                    });
                    block_entries.push(BlockEntry {
                        stored_offset: 0,
                        stored_len: 0,
                        raw_offset,
                        raw_len: input.data.len() as u64,
                        compression: plan.compression_mode,
                    });
                    raw_payload.extend_from_slice(&input.data);
                    raw_offset += input.data.len() as u64;
                }
                payload = compress(plan.compression_mode, &raw_payload);
                for entry in &mut block_entries {
                    entry.stored_len = payload.len() as u64;
                }
            }
        }

        let manifest = Manifest {
            format_version: plan.format_version,
            signature_algorithm: plan.signature_algorithm,
            signature_placement: plan.signature_placement,
            signature_scope: plan.signature_scope,
            manifest_encoding: plan.manifest_encoding,
            compression_mode: plan.compression_mode,
            compression_layout: plan.compression_layout,
            files: manifest_files,
        };
        let manifest_bytes = manifest.serialize()?;
        let block_table = BlockTable {
            entries: block_entries,
        };
        let block_table_bytes = block_table.serialize();
        let header = ArchiveHeader {
            format_version: plan.format_version,
            manifest_encoding: plan.manifest_encoding,
            signature_placement: plan.signature_placement,
            signature_scope: plan.signature_scope,
            compression_mode: plan.compression_mode,
            compression_layout: plan.compression_layout,
            flags: 0,
            manifest_len: manifest_bytes.len() as u64,
            block_table_len: block_table_bytes.len() as u64,
            payload_len: payload.len() as u64,
            signature_len: 0,
            recipient_records_len: 0,
        };

        Ok(Self {
            header,
            manifest,
            manifest_bytes,
            block_table,
            block_table_bytes,
            payload,
            signature: None,
        })
    }

    pub fn read_from_path(path: &Path) -> Result<Self> {
        let bytes = read_bytes(path)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < ArchiveHeader::SIZE {
            return Err(QsrlError::InvalidFormat(
                "archive is smaller than the fixed QSRL header".into(),
            ));
        }

        let header = ArchiveHeader::deserialize(&bytes[..ArchiveHeader::SIZE])?;
        let manifest_start = ArchiveHeader::SIZE;
        let manifest_end = checked_end(manifest_start, header.manifest_len as usize, bytes.len())?;
        let block_table_end =
            checked_end(manifest_end, header.block_table_len as usize, bytes.len())?;
        let payload_end = checked_end(block_table_end, header.payload_len as usize, bytes.len())?;
        let signature_end = checked_end(payload_end, header.signature_len as usize, bytes.len())?;

        let manifest_bytes = bytes[manifest_start..manifest_end].to_vec();
        let block_table_bytes = bytes[manifest_end..block_table_end].to_vec();
        let payload = bytes[block_table_end..payload_end].to_vec();
        let signature = if header.signature_len > 0 {
            Some(SignatureRecord::deserialize(
                &bytes[payload_end..signature_end],
            )?)
        } else {
            None
        };

        let manifest = Manifest::deserialize(&manifest_bytes, header.manifest_encoding)?;
        let block_table = BlockTable::deserialize(&block_table_bytes)?;
        if manifest.files.len() != block_table.entries.len() {
            return Err(QsrlError::InvalidFormat(format!(
                "manifest has {} files but block table has {} entries",
                manifest.files.len(),
                block_table.entries.len()
            )));
        }

        Ok(Self {
            header,
            manifest,
            manifest_bytes,
            block_table,
            block_table_bytes,
            payload,
            signature,
        })
    }

    pub fn write_to_path(&mut self, path: &Path) -> Result<()> {
        self.refresh_header();
        let bytes = self.to_bytes();
        write_bytes(path, &bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = self.header.serialize();
        output.extend_from_slice(&self.manifest_bytes);
        output.extend_from_slice(&self.block_table_bytes);
        output.extend_from_slice(&self.payload);
        if self.header.signature_placement == SignaturePlacement::Embedded {
            if let Some(signature) = &self.signature {
                output.extend_from_slice(&signature.serialize());
            }
        }
        output
    }

    pub fn set_signature_placement(&mut self, placement: SignaturePlacement) -> Result<()> {
        self.manifest.signature_placement = placement;
        self.header.signature_placement = placement;
        self.manifest_bytes = self.manifest.serialize()?;
        if placement == SignaturePlacement::Detached {
            self.signature = None;
        }
        self.refresh_header();
        Ok(())
    }

    pub fn set_embedded_signature(&mut self, signature: SignatureRecord) {
        self.header.signature_placement = SignaturePlacement::Embedded;
        self.manifest.signature_placement = SignaturePlacement::Embedded;
        self.signature = Some(signature);
        self.refresh_header();
    }

    pub fn signed_payload(&self) -> Result<Vec<u8>> {
        match self.manifest.signature_scope {
            SignatureScope::Manifest => Ok(self.manifest_bytes.clone()),
            SignatureScope::ManifestAndBlockTable => {
                let mut bytes =
                    Vec::with_capacity(self.manifest_bytes.len() + self.block_table_bytes.len());
                bytes.extend_from_slice(&self.manifest_bytes);
                bytes.extend_from_slice(&self.block_table_bytes);
                Ok(bytes)
            }
            SignatureScope::PerFileExperimental => Err(QsrlError::UnsupportedFeature(
                "per-file signatures are reserved but not implemented in this prototype".into(),
            )),
        }
    }

    pub fn payload_offset(&self) -> usize {
        ArchiveHeader::SIZE + self.manifest_bytes.len() + self.block_table_bytes.len()
    }

    pub fn extract_files(&self) -> Result<Vec<Vec<u8>>> {
        match self.manifest.compression_layout {
            CompressionLayout::PerFile => self.extract_per_file_payloads(),
            CompressionLayout::WholeArchive => self.extract_whole_archive_payloads(),
        }
    }

    pub fn verify_file_hashes(&self) -> Result<()> {
        let files = self.extract_files()?;
        for ((entry, data), block) in self
            .manifest
            .files
            .iter()
            .zip(files.iter())
            .zip(self.block_table.entries.iter())
        {
            if data.len() as u64 != entry.size {
                return Err(QsrlError::DataCorruption(format!(
                    "file '{}' decoded to {} bytes but manifest expected {}",
                    entry.path,
                    data.len(),
                    entry.size
                )));
            }
            if data.len() as u64 != block.raw_len {
                return Err(QsrlError::DataCorruption(format!(
                    "file '{}' decoded to {} bytes but block table expected {}",
                    entry.path,
                    data.len(),
                    block.raw_len
                )));
            }
            let actual = digest(data);
            if actual != entry.sha256 {
                return Err(QsrlError::DataCorruption(format!(
                    "file '{}' hash did not match the manifest",
                    entry.path
                )));
            }
        }
        Ok(())
    }

    fn refresh_header(&mut self) {
        self.header.manifest_len = self.manifest_bytes.len() as u64;
        self.header.block_table_len = self.block_table_bytes.len() as u64;
        self.header.payload_len = self.payload.len() as u64;
        self.header.signature_len =
            if self.header.signature_placement == SignaturePlacement::Embedded {
                self.signature
                    .as_ref()
                    .map(|value| value.serialize().len() as u64)
                    .unwrap_or(0)
            } else {
                0
            };
        self.header.flags = u8::from(
            self.header.signature_placement == SignaturePlacement::Embedded
                && self.signature.is_some(),
        );
    }

    fn extract_per_file_payloads(&self) -> Result<Vec<Vec<u8>>> {
        let mut files = Vec::with_capacity(self.block_table.entries.len());
        for entry in &self.block_table.entries {
            let start = entry.stored_offset as usize;
            let end = start
                .checked_add(entry.stored_len as usize)
                .ok_or_else(|| QsrlError::DataCorruption("stored block overflow".into()))?;
            if end > self.payload.len() {
                return Err(QsrlError::DataCorruption(
                    "block table points beyond the payload section".into(),
                ));
            }
            let stored = &self.payload[start..end];
            let raw = decompress(entry.compression, stored, Some(entry.raw_len as usize))?;
            files.push(raw);
        }
        Ok(files)
    }

    fn extract_whole_archive_payloads(&self) -> Result<Vec<Vec<u8>>> {
        let total_raw_len = self
            .block_table
            .entries
            .iter()
            .map(|entry| entry.raw_offset + entry.raw_len)
            .max()
            .unwrap_or(0) as usize;
        let raw_payload = decompress(
            self.manifest.compression_mode,
            &self.payload,
            Some(total_raw_len),
        )?;
        let mut files = Vec::with_capacity(self.block_table.entries.len());
        for entry in &self.block_table.entries {
            let start = entry.raw_offset as usize;
            let end = start
                .checked_add(entry.raw_len as usize)
                .ok_or_else(|| QsrlError::DataCorruption("raw block overflow".into()))?;
            if end > raw_payload.len() {
                return Err(QsrlError::DataCorruption(
                    "whole-archive block table points beyond the decompressed payload".into(),
                ));
            }
            files.push(raw_payload[start..end].to_vec());
        }
        Ok(files)
    }
}

pub fn default_detached_signature_path(archive_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", archive_path.display()))
}

fn checked_end(start: usize, len: usize, max: usize) -> Result<usize> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| QsrlError::InvalidFormat("archive section length overflowed".into()))?;
    if end > max {
        return Err(QsrlError::InvalidFormat(
            "archive section extends past the end of the file".into(),
        ));
    }
    Ok(end)
}
