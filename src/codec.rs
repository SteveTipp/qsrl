use crate::error::{QsrlError, Result};
use crate::protocol::CompressionMode;

pub fn compress(mode: CompressionMode, data: &[u8]) -> Vec<u8> {
    match mode {
        CompressionMode::None => data.to_vec(),
        CompressionMode::Rle => compress_rle(data),
    }
}

pub fn decompress(
    mode: CompressionMode,
    data: &[u8],
    expected_len: Option<usize>,
) -> Result<Vec<u8>> {
    let output = match mode {
        CompressionMode::None => data.to_vec(),
        CompressionMode::Rle => decompress_rle(data)?,
    };
    if let Some(expected_len) = expected_len {
        if output.len() != expected_len {
            return Err(QsrlError::DataCorruption(format!(
                "decompressed payload length {} did not match expected {expected_len}",
                output.len()
            )));
        }
    }
    Ok(output)
}

fn compress_rle(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    let mut output = Vec::with_capacity(data.len());
    let mut current = data[0];
    let mut count = 1u8;
    for &byte in &data[1..] {
        if byte == current && count < u8::MAX {
            count += 1;
            continue;
        }
        output.push(count);
        output.push(current);
        current = byte;
        count = 1;
    }
    output.push(count);
    output.push(current);
    output
}

fn decompress_rle(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 2 != 0 {
        return Err(QsrlError::DataCorruption(
            "RLE payload must contain count/value pairs".into(),
        ));
    }

    let mut output = Vec::new();
    for pair in data.chunks_exact(2) {
        output.extend(std::iter::repeat_n(pair[1], pair[0] as usize));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{compress, decompress};
    use crate::protocol::CompressionMode;

    #[test]
    fn rle_round_trip() {
        let raw = b"aaaaabbbbbcccccccccccc";
        let compressed = compress(CompressionMode::Rle, raw);
        let decompressed =
            decompress(CompressionMode::Rle, &compressed, Some(raw.len())).expect("rle decode");
        assert_eq!(decompressed, raw);
    }
}
