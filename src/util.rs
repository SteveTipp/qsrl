use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{QsrlError, Result};

#[derive(Clone, Debug)]
pub struct InputFile {
    pub path: String,
    pub data: Vec<u8>,
}

pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| QsrlError::io("creating parent directory", err))?;
    }
    Ok(())
}

pub fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure_parent_dir(path)?;
    fs::write(path, bytes).map_err(|err| QsrlError::io(format!("writing {}", path.display()), err))
}

pub fn write_string(path: &Path, contents: &str) -> Result<()> {
    write_bytes(path, contents.as_bytes())
}

pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|err| QsrlError::io(format!("reading {}", path.display()), err))
}

pub fn read_string(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .map_err(|err| QsrlError::io(format!("reading {}", path.display()), err))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub fn hex_decode(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.len() % 2 != 0 {
        return Err(QsrlError::Parse(
            "hex value must contain an even number of characters".into(),
        ));
    }

    let mut output = Vec::with_capacity(trimmed.len() / 2);
    for chunk in trimmed.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(QsrlError::Parse(format!(
            "invalid hex character '{}'",
            value as char
        ))),
    }
}

pub fn push_u16_le(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

pub fn push_u32_le(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

pub fn push_u64_le(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

pub fn read_u16_le(bytes: &[u8], cursor: &mut usize, context: &str) -> Result<u16> {
    let slice = take_bytes(bytes, cursor, 2, context)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub fn read_u32_le(bytes: &[u8], cursor: &mut usize, context: &str) -> Result<u32> {
    let slice = take_bytes(bytes, cursor, 4, context)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn read_u64_le(bytes: &[u8], cursor: &mut usize, context: &str) -> Result<u64> {
    let slice = take_bytes(bytes, cursor, 8, context)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

pub fn take_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
    context: &str,
) -> Result<&'a [u8]> {
    if *cursor + len > bytes.len() {
        return Err(QsrlError::InvalidFormat(format!(
            "truncated {context}: expected {len} more bytes"
        )));
    }
    let slice = &bytes[*cursor..*cursor + len];
    *cursor += len;
    Ok(slice)
}

pub fn collect_input_files(input_path: &Path) -> Result<Vec<InputFile>> {
    let metadata = fs::metadata(input_path).map_err(|err| {
        QsrlError::io(
            format!("reading metadata for {}", input_path.display()),
            err,
        )
    })?;

    let mut files = Vec::new();
    if metadata.is_file() {
        let filename = input_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| QsrlError::Parse("input filename must be valid UTF-8".into()))?;
        let normalized = normalize_path_string(filename)?;
        files.push(InputFile {
            path: normalized,
            data: read_bytes(input_path)?,
        });
    } else if metadata.is_dir() {
        collect_dir_recursive(input_path, input_path, &mut files)?;
    } else {
        return Err(QsrlError::Usage(format!(
            "{} is neither a file nor a directory",
            input_path.display()
        )));
    }

    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect_dir_recursive(base: &Path, current: &Path, files: &mut Vec<InputFile>) -> Result<()> {
    let mut entries: Vec<PathBuf> = fs::read_dir(current)
        .map_err(|err| QsrlError::io(format!("reading directory {}", current.display()), err))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| QsrlError::io("reading directory entry", err))?;
    entries.sort();

    for path in entries {
        let metadata = fs::symlink_metadata(&path).map_err(|err| {
            QsrlError::io(format!("reading metadata for {}", path.display()), err)
        })?;
        if metadata.file_type().is_symlink() {
            return Err(QsrlError::UnsupportedFeature(format!(
                "symlinks are not supported in this prototype: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_dir_recursive(base, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(base)
                .map_err(|_| QsrlError::Parse("failed to normalize input path".into()))?;
            let normalized = normalize_path(relative)?;
            files.push(InputFile {
                path: normalized,
                data: read_bytes(&path)?,
            });
        }
    }

    Ok(())
}

pub fn normalize_path(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| QsrlError::Parse("path must be valid UTF-8 in this prototype".into()))?;
    normalize_path_string(value)
}

pub fn normalize_path_string(value: &str) -> Result<String> {
    if value.contains('\n') || value.contains('\r') {
        return Err(QsrlError::UnsupportedFeature(
            "paths containing newlines are not supported".into(),
        ));
    }
    let normalized = value.replace('\\', "/");
    if normalized.starts_with("../") || normalized == ".." {
        return Err(QsrlError::Usage(
            "paths escaping the input root are not supported".into(),
        ));
    }
    Ok(normalized)
}

pub fn unique_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}-{:x}", std::process::id(), nanos)
}

pub fn read_random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; len];
    match fs::File::open("/dev/urandom") {
        Ok(mut file) => {
            file.read_exact(&mut buffer)
                .map_err(|err| QsrlError::io("reading /dev/urandom", err))?;
            Ok(buffer)
        }
        Err(_) => Ok(fallback_random_bytes(len)),
    }
}

fn fallback_random_bytes(len: usize) -> Vec<u8> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut state = (nanos as u64) ^ ((std::process::id() as u64) << 16);
    let mut buffer = vec![0u8; len];
    for byte in &mut buffer {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xff) as u8;
    }
    buffer
}

#[cfg(test)]
mod tests {
    use super::{hex_decode, hex_encode};

    #[test]
    fn hex_round_trip() {
        let data = vec![0, 1, 2, 15, 16, 255];
        let encoded = hex_encode(&data);
        let decoded = hex_decode(&encoded).expect("hex decode should work");
        assert_eq!(decoded, data);
    }
}
