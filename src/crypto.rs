use std::path::Path;

use crate::error::{QsrlError, Result};
use crate::protocol::SignatureAlgorithm;
use crate::sha256::{digest, digest_parts};
use crate::util::{
    hex_decode, hex_encode, read_bytes, read_random_bytes, read_string, write_string,
};

pub const STUB_IMPLEMENTATION_CODE: u8 = 1;
pub const STUB_IMPLEMENTATION_LABEL: &str = "stub-lamport-v1";

#[derive(Clone, Debug)]
pub struct PrivateKey {
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub challenge_bits: usize,
    pub secret_size: usize,
    pub public_key_fingerprint: [u8; 32],
    pub public_hashes: Vec<[u8; 32]>,
    pub secret_values: Vec<Vec<u8>>,
    pub uses: u32,
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub challenge_bits: usize,
    pub secret_size: usize,
    pub fingerprint: [u8; 32],
    pub public_hashes: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Debug)]
struct StubParams {
    challenge_bits: usize,
    secret_size: usize,
}

pub fn generate_keypair(
    algorithm: SignatureAlgorithm,
    key_id: String,
) -> Result<(PrivateKey, PublicKey)> {
    let params = params_for_algorithm(algorithm);
    let pair_count = params.challenge_bits * 2;
    let mut public_hashes = Vec::with_capacity(pair_count);
    let mut secret_values = Vec::with_capacity(pair_count);

    for index in 0..pair_count {
        let secret = read_random_bytes(params.secret_size)?;
        let public_hash = public_value_hash(algorithm, index, &secret);
        public_hashes.push(public_hash);
        secret_values.push(secret);
    }

    let fingerprint = public_key_fingerprint(algorithm, &public_hashes);
    let private_key = PrivateKey {
        algorithm,
        key_id: key_id.clone(),
        challenge_bits: params.challenge_bits,
        secret_size: params.secret_size,
        public_key_fingerprint: fingerprint,
        public_hashes: public_hashes.clone(),
        secret_values,
        uses: 0,
    };
    let public_key = PublicKey {
        algorithm,
        key_id,
        challenge_bits: params.challenge_bits,
        secret_size: params.secret_size,
        fingerprint,
        public_hashes,
    };
    Ok((private_key, public_key))
}

pub fn sign_message(private_key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>> {
    let challenge = challenge_bytes(private_key.algorithm, message);
    let expected_bits = private_key.challenge_bits;
    if challenge.len() * 8 != expected_bits {
        return Err(QsrlError::KeyRejected(
            "private key challenge width does not match algorithm".into(),
        ));
    }

    let mut signature = Vec::with_capacity(expected_bits * private_key.secret_size);
    for bit_index in 0..expected_bits {
        let bit = challenge_bit(&challenge, bit_index);
        let source_index = bit_index * 2 + bit;
        signature.extend_from_slice(&private_key.secret_values[source_index]);
    }
    Ok(signature)
}

pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    let challenge = challenge_bytes(public_key.algorithm, message);
    let expected_bits = public_key.challenge_bits;
    if challenge.len() * 8 != expected_bits {
        return Err(QsrlError::SignatureVerificationFailed(
            "challenge width does not match public key".into(),
        ));
    }
    let expected_len = expected_bits * public_key.secret_size;
    if signature.len() != expected_len {
        return Err(QsrlError::SignatureVerificationFailed(format!(
            "signature length {} did not match expected {expected_len}",
            signature.len()
        )));
    }

    for bit_index in 0..expected_bits {
        let bit = challenge_bit(&challenge, bit_index);
        let start = bit_index * public_key.secret_size;
        let end = start + public_key.secret_size;
        let revealed = &signature[start..end];
        let candidate_hash = public_value_hash(public_key.algorithm, bit_index * 2 + bit, revealed);
        let expected_hash = public_key.public_hashes[bit_index * 2 + bit];
        if candidate_hash != expected_hash {
            return Err(QsrlError::SignatureVerificationFailed(format!(
                "signature mismatch at challenge position {bit_index}"
            )));
        }
    }

    Ok(())
}

pub fn write_private_key(path: &Path, key: &PrivateKey) -> Result<()> {
    let secret_blob: Vec<u8> = key.secret_values.iter().flatten().copied().collect();
    let public_blob: Vec<u8> = key.public_hashes.iter().flatten().copied().collect();
    let contents = format!(
        "# Quantum Sealed Record Layer prototype key file\n\
type = \"private\"\n\
algorithm = \"{}\"\n\
implementation = \"{}\"\n\
key_id = \"{}\"\n\
challenge_bits = {}\n\
secret_size = {}\n\
public_key_fingerprint = \"{}\"\n\
public_hashes = \"{}\"\n\
secret_values = \"{}\"\n\
uses = {}\n",
        key.algorithm.as_str(),
        STUB_IMPLEMENTATION_LABEL,
        key.key_id,
        key.challenge_bits,
        key.secret_size,
        hex_encode(&key.public_key_fingerprint),
        hex_encode(&public_blob),
        hex_encode(&secret_blob),
        key.uses,
    );
    write_string(path, &contents)
}

pub fn write_public_key(path: &Path, key: &PublicKey) -> Result<()> {
    let public_blob: Vec<u8> = key.public_hashes.iter().flatten().copied().collect();
    let contents = format!(
        "# Quantum Sealed Record Layer prototype key file\n\
type = \"public\"\n\
algorithm = \"{}\"\n\
implementation = \"{}\"\n\
key_id = \"{}\"\n\
challenge_bits = {}\n\
secret_size = {}\n\
public_key_fingerprint = \"{}\"\n\
public_hashes = \"{}\"\n",
        key.algorithm.as_str(),
        STUB_IMPLEMENTATION_LABEL,
        key.key_id,
        key.challenge_bits,
        key.secret_size,
        hex_encode(&key.fingerprint),
        hex_encode(&public_blob),
    );
    write_string(path, &contents)
}

pub fn load_private_key(path: &Path) -> Result<PrivateKey> {
    let map = parse_key_file(path)?;
    ensure_key_type(&map, "private")?;
    let algorithm = SignatureAlgorithm::from_str(required_field(&map, "algorithm")?)?;
    ensure_stub_implementation(required_field(&map, "implementation")?)?;
    let key_id = required_field(&map, "key_id")?.to_string();
    let challenge_bits = required_field(&map, "challenge_bits")?
        .parse::<usize>()
        .map_err(|_| QsrlError::Parse("invalid challenge_bits in private key".into()))?;
    let secret_size = required_field(&map, "secret_size")?
        .parse::<usize>()
        .map_err(|_| QsrlError::Parse("invalid secret_size in private key".into()))?;
    let fingerprint = parse_fixed_32(required_field(&map, "public_key_fingerprint")?)?;
    let public_hashes = parse_public_hashes(required_field(&map, "public_hashes")?)?;
    let secret_values = parse_secret_values(
        required_field(&map, "secret_values")?,
        challenge_bits,
        secret_size,
    )?;
    let uses = required_field(&map, "uses")?
        .parse::<u32>()
        .map_err(|_| QsrlError::Parse("invalid uses count in private key".into()))?;

    Ok(PrivateKey {
        algorithm,
        key_id,
        challenge_bits,
        secret_size,
        public_key_fingerprint: fingerprint,
        public_hashes,
        secret_values,
        uses,
    })
}

pub fn load_public_key(path: &Path) -> Result<PublicKey> {
    let map = parse_key_file(path)?;
    ensure_key_type(&map, "public")?;
    let algorithm = SignatureAlgorithm::from_str(required_field(&map, "algorithm")?)?;
    ensure_stub_implementation(required_field(&map, "implementation")?)?;
    let key_id = required_field(&map, "key_id")?.to_string();
    let challenge_bits = required_field(&map, "challenge_bits")?
        .parse::<usize>()
        .map_err(|_| QsrlError::Parse("invalid challenge_bits in public key".into()))?;
    let secret_size = required_field(&map, "secret_size")?
        .parse::<usize>()
        .map_err(|_| QsrlError::Parse("invalid secret_size in public key".into()))?;
    let fingerprint = parse_fixed_32(required_field(&map, "public_key_fingerprint")?)?;
    let public_hashes = parse_public_hashes(required_field(&map, "public_hashes")?)?;

    Ok(PublicKey {
        algorithm,
        key_id,
        challenge_bits,
        secret_size,
        fingerprint,
        public_hashes,
    })
}

pub fn message_digest(message: &[u8]) -> [u8; 32] {
    digest(message)
}

fn params_for_algorithm(algorithm: SignatureAlgorithm) -> StubParams {
    match algorithm {
        SignatureAlgorithm::MlDsa => StubParams {
            challenge_bits: 256,
            secret_size: 32,
        },
        SignatureAlgorithm::SlhDsa => StubParams {
            challenge_bits: 512,
            secret_size: 64,
        },
    }
}

fn challenge_bytes(algorithm: SignatureAlgorithm, message: &[u8]) -> Vec<u8> {
    match algorithm {
        SignatureAlgorithm::MlDsa => {
            digest_parts(&[b"QSRL-STUB-ML-DSA-CHALLENGE", message]).to_vec()
        }
        SignatureAlgorithm::SlhDsa => {
            let first = digest_parts(&[b"QSRL-STUB-SLH-DSA-CHALLENGE-A", message]);
            let second = digest_parts(&[b"QSRL-STUB-SLH-DSA-CHALLENGE-B", message]);
            [first.to_vec(), second.to_vec()].concat()
        }
    }
}

fn challenge_bit(challenge: &[u8], bit_index: usize) -> usize {
    let byte = challenge[bit_index / 8];
    let shift = 7 - (bit_index % 8);
    ((byte >> shift) & 1) as usize
}

fn public_value_hash(algorithm: SignatureAlgorithm, index: usize, secret: &[u8]) -> [u8; 32] {
    let index_bytes = (index as u32).to_le_bytes();
    digest_parts(&[
        b"QSRL-STUB-LAMPORT-PUBLIC",
        algorithm.as_str().as_bytes(),
        &index_bytes,
        secret,
    ])
}

fn public_key_fingerprint(algorithm: SignatureAlgorithm, public_hashes: &[[u8; 32]]) -> [u8; 32] {
    let public_blob: Vec<u8> = public_hashes.iter().flatten().copied().collect();
    digest_parts(&[
        b"QSRL-STUB-LAMPORT-FINGERPRINT",
        algorithm.as_str().as_bytes(),
        &public_blob,
    ])
}

fn parse_key_file(path: &Path) -> Result<std::collections::BTreeMap<String, String>> {
    let contents = read_string(path)?;
    let mut fields = std::collections::BTreeMap::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| QsrlError::Parse(format!("invalid key file line '{line}'")))?;
        fields.insert(
            key.trim().to_string(),
            value.trim().trim_matches('"').to_string(),
        );
    }
    Ok(fields)
}

fn required_field<'a>(
    fields: &'a std::collections::BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str> {
    fields
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| QsrlError::Parse(format!("key file missing '{name}'")))
}

fn ensure_key_type(
    fields: &std::collections::BTreeMap<String, String>,
    expected_type: &str,
) -> Result<()> {
    let actual = required_field(fields, "type")?;
    if actual != expected_type {
        return Err(QsrlError::KeyRejected(format!(
            "expected a {expected_type} key file but found '{actual}'"
        )));
    }
    Ok(())
}

fn ensure_stub_implementation(value: &str) -> Result<()> {
    if value != STUB_IMPLEMENTATION_LABEL {
        return Err(QsrlError::UnsupportedFeature(format!(
            "unsupported key implementation '{value}'"
        )));
    }
    Ok(())
}

fn parse_fixed_32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex_decode(value)?;
    if bytes.len() != 32 {
        return Err(QsrlError::Parse(
            "expected a 32-byte hex-encoded value".into(),
        ));
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    Ok(output)
}

fn parse_public_hashes(value: &str) -> Result<Vec<[u8; 32]>> {
    let bytes = hex_decode(value)?;
    if bytes.len() % 32 != 0 {
        return Err(QsrlError::Parse(
            "public_hashes must contain a whole number of 32-byte entries".into(),
        ));
    }
    let mut hashes = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks_exact(32) {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(chunk);
        hashes.push(hash);
    }
    Ok(hashes)
}

fn parse_secret_values(
    value: &str,
    challenge_bits: usize,
    secret_size: usize,
) -> Result<Vec<Vec<u8>>> {
    let bytes = hex_decode(value)?;
    let pair_count = challenge_bits * 2;
    let expected_len = pair_count * secret_size;
    if bytes.len() != expected_len {
        return Err(QsrlError::Parse(format!(
            "secret_values length {} did not match expected {expected_len}",
            bytes.len()
        )));
    }
    let mut values = Vec::with_capacity(pair_count);
    for chunk in bytes.chunks_exact(secret_size) {
        values.push(chunk.to_vec());
    }
    Ok(values)
}

pub fn detached_signature_bytes(path: &Path) -> Result<Vec<u8>> {
    read_bytes(path)
}

#[cfg(test)]
mod tests {
    use super::{generate_keypair, sign_message, verify_signature};
    use crate::protocol::SignatureAlgorithm;

    #[test]
    fn stub_signature_round_trip() {
        let (private_key, public_key) =
            generate_keypair(SignatureAlgorithm::MlDsa, "test".into()).expect("keygen");
        let message = b"manifest bytes";
        let signature = sign_message(&private_key, message).expect("sign");
        verify_signature(&public_key, message, &signature).expect("verify");
    }
}
