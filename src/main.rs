use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use qsrl::commands::{
    SettingsOverrides, compare_protocols, init_repo, inspect_archive, keygen, pack_archive,
    sign_archive, verify_archive,
};
use qsrl::error::{QsrlError, Result};
use qsrl::protocol::{
    CompressionLayout, CompressionMode, ManifestEncoding, SignatureAlgorithm, SignaturePlacement,
    SignatureScope,
};

fn main() {
    match run() {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Err(error) => {
            eprintln!("qsrl: {error}");
            std::process::exit(error.exit_code());
        }
    }
}

fn run() -> Result<String> {
    let args: Vec<String> = env::args().collect();
    if args.len() <= 1 {
        return Ok(usage());
    }
    if matches!(args[1].as_str(), "--help" | "-h" | "help") {
        return Ok(usage());
    }

    let cwd = env::current_dir().map_err(|err| QsrlError::io("reading current directory", err))?;
    let command = &args[1];
    let parsed = ParsedArgs::parse(&args[2..])?;

    match command.as_str() {
        "init" => init_repo(&cwd, parsed.settings_overrides()?),
        "pack" => {
            let input_path = parsed.required_positional(0, "pack requires <input_path>")?;
            let output_path = parsed.required_path(["-o", "--output"])?;
            pack_archive(
                &cwd,
                Path::new(input_path),
                &output_path,
                parsed.settings_overrides()?,
            )
        }
        "keygen" => {
            let algorithm = SignatureAlgorithm::from_str(parsed.required_value(["--alg"])?)?;
            keygen(&cwd, algorithm)
        }
        "sign" => {
            let archive_path =
                PathBuf::from(parsed.required_positional(0, "sign requires <archive.qsrl>")?);
            let key_path = parsed.required_path(["--key"])?;
            let placement = parsed
                .optional_value(["--placement"])?
                .map(SignaturePlacement::from_str)
                .transpose()?;
            let signature_path = parsed.optional_path(["--sig"])?;
            sign_archive(
                &archive_path,
                &key_path,
                placement,
                signature_path.as_deref(),
            )
        }
        "verify" => {
            let archive_path =
                PathBuf::from(parsed.required_positional(0, "verify requires <archive.qsrl>")?);
            let public_key_path = parsed.required_path(["--pubkey"])?;
            let signature_path = parsed.optional_path(["--sig"])?;
            verify_archive(&archive_path, &public_key_path, signature_path.as_deref())
        }
        "inspect" => {
            let archive_path =
                PathBuf::from(parsed.required_positional(0, "inspect requires <archive.qsrl>")?);
            inspect_archive(&archive_path)
        }
        "compare" => {
            let input_path =
                PathBuf::from(parsed.required_positional(0, "compare requires <input_path>")?);
            let output_path = parsed.required_path(["-o", "--output"])?;
            let key_path = parsed.required_path(["--key"])?;
            compare_protocols(&cwd, &input_path, &output_path, &key_path)
        }
        other => Err(QsrlError::Usage(format!(
            "unknown command '{other}'\n\n{}",
            usage()
        ))),
    }
}

#[derive(Debug)]
struct ParsedArgs {
    positionals: Vec<String>,
    options: BTreeMap<String, String>,
}

impl ParsedArgs {
    fn parse(args: &[String]) -> Result<Self> {
        let mut positionals = Vec::new();
        let mut options = BTreeMap::new();
        let mut index = 0usize;
        while index < args.len() {
            let arg = &args[index];
            if arg.starts_with('-') {
                if matches!(arg.as_str(), "--help" | "-h") {
                    return Err(QsrlError::Usage(usage()));
                }
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| QsrlError::Usage(format!("missing value for option '{arg}'")))?;
                options.insert(arg.clone(), value.clone());
                index += 2;
            } else {
                positionals.push(arg.clone());
                index += 1;
            }
        }

        Ok(Self {
            positionals,
            options,
        })
    }

    fn required_positional(&self, index: usize, message: &str) -> Result<&str> {
        self.positionals
            .get(index)
            .map(String::as_str)
            .ok_or_else(|| QsrlError::Usage(message.into()))
    }

    fn optional_value<const N: usize>(&self, names: [&str; N]) -> Result<Option<&str>> {
        Ok(names
            .iter()
            .find_map(|name| self.options.get(*name).map(String::as_str)))
    }

    fn required_value<const N: usize>(&self, names: [&str; N]) -> Result<&str> {
        self.optional_value(names)?.ok_or_else(|| {
            QsrlError::Usage(format!("missing required option {}", names.join(" or ")))
        })
    }

    fn required_path<const N: usize>(&self, names: [&str; N]) -> Result<PathBuf> {
        Ok(PathBuf::from(self.required_value(names)?))
    }

    fn optional_path<const N: usize>(&self, names: [&str; N]) -> Result<Option<PathBuf>> {
        Ok(self.optional_value(names)?.map(PathBuf::from))
    }

    fn settings_overrides(&self) -> Result<SettingsOverrides> {
        Ok(SettingsOverrides {
            format_version: self
                .optional_value(["--format-version"])?
                .map(|value| {
                    value
                        .parse::<u16>()
                        .map_err(|_| QsrlError::Parse("invalid --format-version".into()))
                })
                .transpose()?,
            signature_algorithm: self
                .optional_value(["--alg"])?
                .map(SignatureAlgorithm::from_str)
                .transpose()?,
            signature_placement: self
                .optional_value(["--placement"])?
                .map(SignaturePlacement::from_str)
                .transpose()?,
            signature_scope: self
                .optional_value(["--scope"])?
                .map(SignatureScope::from_str)
                .transpose()?,
            manifest_encoding: self
                .optional_value(["--manifest-encoding"])?
                .map(ManifestEncoding::from_str)
                .transpose()?,
            compression_mode: self
                .optional_value(["--compression"])?
                .map(CompressionMode::from_str)
                .transpose()?,
            compression_layout: self
                .optional_value(["--compression-layout"])?
                .map(CompressionLayout::from_str)
                .transpose()?,
        })
    }
}

fn usage() -> String {
    "\
Quantum Sealed Record Layer (QSRL)

Usage:
  qsrl init [--alg ml-dsa|slh-dsa] [--placement embedded|detached] [--scope manifest|manifest+block-table] [--manifest-encoding text-v1|binary-v1] [--compression none|rle] [--compression-layout per-file|whole-archive]
  qsrl pack <input_path> -o <archive.qsrl> [--alg ml-dsa|slh-dsa] [--placement embedded|detached] [--scope manifest|manifest+block-table] [--manifest-encoding text-v1|binary-v1] [--compression none|rle] [--compression-layout per-file|whole-archive]
  qsrl keygen --alg ml-dsa|slh-dsa
  qsrl sign <archive.qsrl> --key <private_key> [--placement embedded|detached] [--sig <signature.sig>]
  qsrl verify <archive.qsrl> --pubkey <public_key> [--sig <signature.sig>]
  qsrl inspect <archive.qsrl>
  qsrl compare <input_path> -o <output_dir> --key <private_key>

Notes:
  - This prototype uses the QSRL names ML-DSA and SLH-DSA throughout the UX.
  - Default builds use the documented stub backend; use `--features liboqs-backend` for real liboqs-backed ML-DSA and SLH-DSA operations.
  - This prototype is for experimentation, not a production security claim.
  - Archives use the .qsrl extension.
"
    .into()
}
