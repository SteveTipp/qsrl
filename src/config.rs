use std::path::{Path, PathBuf};

use crate::FORMAT_VERSION;
use crate::error::{QsrlError, Result};
use crate::protocol::{
    CompressionLayout, CompressionMode, ManifestEncoding, SignatureAlgorithm, SignaturePlacement,
    SignatureScope,
};
use crate::util::{read_string, write_string};

#[derive(Clone, Debug)]
pub struct RepoConfig {
    pub format_version: u16,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature_placement: SignaturePlacement,
    pub signature_scope: SignatureScope,
    pub manifest_encoding: ManifestEncoding,
    pub compression_mode: CompressionMode,
    pub compression_layout: CompressionLayout,
}

impl Default for RepoConfig {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            signature_algorithm: SignatureAlgorithm::MlDsa,
            signature_placement: SignaturePlacement::Embedded,
            signature_scope: SignatureScope::Manifest,
            manifest_encoding: ManifestEncoding::TextV1,
            compression_mode: CompressionMode::None,
            compression_layout: CompressionLayout::PerFile,
        }
    }
}

impl RepoConfig {
    pub fn path(root: &Path) -> PathBuf {
        root.join(".qsrl").join("config.toml")
    }

    pub fn load_or_default(root: &Path) -> Result<Self> {
        let path = Self::path(root);
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::load(root)
    }

    pub fn load(root: &Path) -> Result<Self> {
        let path = Self::path(root);
        let contents = read_string(&path)?;
        let mut config = Self::default();

        for raw_line in contents.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| QsrlError::Parse(format!("invalid config line '{line}'")))?;
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match key {
                "format_version" => {
                    config.format_version = value
                        .parse::<u16>()
                        .map_err(|_| QsrlError::Parse("invalid format_version".into()))?
                }
                "signature_algorithm" => {
                    config.signature_algorithm = SignatureAlgorithm::from_str(value)?
                }
                "signature_placement" => {
                    config.signature_placement = SignaturePlacement::from_str(value)?
                }
                "signature_scope" => config.signature_scope = SignatureScope::from_str(value)?,
                "manifest_encoding" => {
                    config.manifest_encoding = ManifestEncoding::from_str(value)?
                }
                "compression_mode" => config.compression_mode = CompressionMode::from_str(value)?,
                "compression_layout" => {
                    config.compression_layout = CompressionLayout::from_str(value)?
                }
                other => return Err(QsrlError::Parse(format!("unknown config key '{other}'"))),
            }
        }

        Ok(config)
    }

    pub fn save(&self, root: &Path) -> Result<PathBuf> {
        let path = Self::path(root);
        let contents = format!(
            "format_version = {}\nsignature_algorithm = \"{}\"\nsignature_placement = \"{}\"\nsignature_scope = \"{}\"\nmanifest_encoding = \"{}\"\ncompression_mode = \"{}\"\ncompression_layout = \"{}\"\n",
            self.format_version,
            self.signature_algorithm.as_str(),
            self.signature_placement.as_str(),
            self.signature_scope.as_str(),
            self.manifest_encoding.as_str(),
            self.compression_mode.as_str(),
            self.compression_layout.as_str(),
        );
        write_string(&path, &contents)?;
        Ok(path)
    }
}
