use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use crate::error::{QsrlError, Result};
use crate::protocol::{KemAlgorithm, RecipientRecord, SignatureAlgorithm};
use crate::sha256::{digest, digest_parts};
use crate::util::{
    ensure_parent_dir, hex_decode, hex_encode, read_random_bytes, read_string, write_string,
};

pub const STUB_IMPLEMENTATION_CODE: u8 = 1;
pub const STUB_IMPLEMENTATION_LABEL: &str = "stub-lamport-v1";
pub const LIBOQS_IMPLEMENTATION_CODE: u8 = 2;
pub const LIBOQS_IMPLEMENTATION_LABEL: &str = "liboqs-system-v1";

const STUB_METHOD_NAME_ML_DSA: &str = "QSRL-STUB-ML-DSA";
const STUB_METHOD_NAME_SLH_DSA: &str = "QSRL-STUB-SLH-DSA";
#[cfg(feature = "liboqs-backend")]
const LIBOQS_METHOD_NAME_ML_DSA: &str = "ML-DSA-65";
#[cfg(feature = "liboqs-backend")]
const LIBOQS_METHOD_NAME_SLH_DSA: &str = "SLH_DSA_PURE_SHA2_192S";
#[cfg(feature = "liboqs-backend")]
const LIBOQS_METHOD_NAME_ML_KEM: &str = "ML-KEM-768";

pub const ARCHIVE_KEY_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyImplementation {
    StubLamportV1,
    LiboqsSystemV1,
}

impl KeyImplementation {
    pub fn code(self) -> u8 {
        match self {
            Self::StubLamportV1 => STUB_IMPLEMENTATION_CODE,
            Self::LiboqsSystemV1 => LIBOQS_IMPLEMENTATION_CODE,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::StubLamportV1 => STUB_IMPLEMENTATION_LABEL,
            Self::LiboqsSystemV1 => LIBOQS_IMPLEMENTATION_LABEL,
        }
    }

    pub fn from_label(value: &str) -> Result<Self> {
        match value {
            STUB_IMPLEMENTATION_LABEL => Ok(Self::StubLamportV1),
            LIBOQS_IMPLEMENTATION_LABEL => Ok(Self::LiboqsSystemV1),
            other => Err(QsrlError::UnsupportedFeature(format!(
                "unsupported key implementation '{other}'"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PrivateKey {
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub public_key_fingerprint: [u8; 32],
    pub uses: u32,
    pub implementation: KeyImplementation,
    pub method_name: String,
    pub algorithm_version: Option<String>,
    pub library_version: Option<String>,
    pub public_key_bytes: Vec<u8>,
    pub secret_key_bytes: Vec<u8>,
}

impl PrivateKey {
    pub fn implementation_code(&self) -> u8 {
        self.implementation.code()
    }

    pub fn implementation_label(&self) -> &'static str {
        self.implementation.label()
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub fingerprint: [u8; 32],
    pub implementation: KeyImplementation,
    pub method_name: String,
    pub algorithm_version: Option<String>,
    pub library_version: Option<String>,
    pub public_key_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct KemPrivateKey {
    pub algorithm: KemAlgorithm,
    pub key_id: String,
    pub public_key_fingerprint: [u8; 32],
    pub implementation: KeyImplementation,
    pub method_name: String,
    pub algorithm_version: Option<String>,
    pub library_version: Option<String>,
    pub public_key_bytes: Vec<u8>,
    pub secret_key_bytes: Vec<u8>,
}

impl KemPrivateKey {
    pub fn implementation_code(&self) -> u8 {
        self.implementation.code()
    }

    pub fn implementation_label(&self) -> &'static str {
        self.implementation.label()
    }
}

#[derive(Clone, Debug)]
pub struct KemPublicKey {
    pub algorithm: KemAlgorithm,
    pub key_id: String,
    pub fingerprint: [u8; 32],
    pub implementation: KeyImplementation,
    pub method_name: String,
    pub algorithm_version: Option<String>,
    pub library_version: Option<String>,
    pub public_key_bytes: Vec<u8>,
}

impl KemPublicKey {
    pub fn implementation_code(&self) -> u8 {
        self.implementation.code()
    }

    pub fn implementation_label(&self) -> &'static str {
        self.implementation.label()
    }
}

impl PublicKey {
    pub fn implementation_code(&self) -> u8 {
        self.implementation.code()
    }

    pub fn implementation_label(&self) -> &'static str {
        self.implementation.label()
    }
}

#[derive(Clone, Copy, Debug)]
struct StubParams {
    challenge_bits: usize,
    secret_size: usize,
}

pub fn active_implementation() -> KeyImplementation {
    if cfg!(feature = "liboqs-backend") {
        KeyImplementation::LiboqsSystemV1
    } else {
        KeyImplementation::StubLamportV1
    }
}

pub fn generate_keypair(
    algorithm: SignatureAlgorithm,
    key_id: String,
) -> Result<(PrivateKey, PublicKey)> {
    if cfg!(feature = "liboqs-backend") {
        return generate_liboqs_keypair(algorithm, key_id);
    }
    generate_stub_keypair(algorithm, key_id)
}

pub fn sign_message(private_key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>> {
    match private_key.implementation {
        KeyImplementation::StubLamportV1 => sign_stub_message(private_key, message),
        KeyImplementation::LiboqsSystemV1 => sign_liboqs_message(private_key, message),
    }
}

pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    match public_key.implementation {
        KeyImplementation::StubLamportV1 => verify_stub_signature(public_key, message, signature),
        KeyImplementation::LiboqsSystemV1 => {
            verify_liboqs_signature(public_key, message, signature)
        }
    }
}

pub fn generate_recipient_keypair(
    algorithm: KemAlgorithm,
    key_id: String,
) -> Result<(KemPrivateKey, KemPublicKey)> {
    if cfg!(feature = "liboqs-backend") {
        return generate_liboqs_kem_keypair(algorithm, key_id);
    }
    Err(QsrlError::UnsupportedFeature(
        "recipient encryption requires the liboqs backend; rebuild with --features liboqs-backend"
            .into(),
    ))
}

pub fn wrap_archive_key_for_recipient(
    public_key: &KemPublicKey,
    archive_key: &[u8],
) -> Result<RecipientRecord> {
    if archive_key.len() != ARCHIVE_KEY_LEN {
        return Err(QsrlError::UnsupportedFeature(format!(
            "archive key length {} did not match expected {ARCHIVE_KEY_LEN}",
            archive_key.len()
        )));
    }
    match public_key.implementation {
        KeyImplementation::LiboqsSystemV1 => wrap_archive_key_liboqs(public_key, archive_key),
        KeyImplementation::StubLamportV1 => Err(QsrlError::UnsupportedFeature(
            "recipient encryption is not available with the stub backend".into(),
        )),
    }
}

pub fn unwrap_archive_key_for_recipient(
    private_key: &KemPrivateKey,
    record: &RecipientRecord,
) -> Result<Vec<u8>> {
    match private_key.implementation {
        KeyImplementation::LiboqsSystemV1 => unwrap_archive_key_liboqs(private_key, record),
        KeyImplementation::StubLamportV1 => Err(QsrlError::UnsupportedFeature(
            "recipient encryption is not available with the stub backend".into(),
        )),
    }
}

pub fn encrypt_aead(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "liboqs-backend")]
    {
        openssl_aead::encrypt_aes_256_gcm(key, nonce, aad, plaintext)
    }
    #[cfg(not(feature = "liboqs-backend"))]
    {
        let _ = key;
        let _ = nonce;
        let _ = aad;
        let _ = plaintext;
        Err(QsrlError::UnsupportedFeature(
            "AEAD encryption requires the liboqs backend build in this prototype".into(),
        ))
    }
}

pub fn decrypt_aead(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    #[cfg(feature = "liboqs-backend")]
    {
        openssl_aead::decrypt_aes_256_gcm(key, nonce, aad, ciphertext, tag)
    }
    #[cfg(not(feature = "liboqs-backend"))]
    {
        let _ = key;
        let _ = nonce;
        let _ = aad;
        let _ = ciphertext;
        let _ = tag;
        Err(QsrlError::UnsupportedFeature(
            "AEAD decryption requires the liboqs backend build in this prototype".into(),
        ))
    }
}

pub fn write_private_key(path: &Path, key: &PrivateKey) -> Result<()> {
    write_private_key_file(path, &private_key_contents(key), true)
}

pub fn write_new_private_key(path: &Path, key: &PrivateKey) -> Result<()> {
    write_private_key_file(path, &private_key_contents(key), false)
}

fn private_key_contents(key: &PrivateKey) -> String {
    let mut contents = String::new();
    contents.push_str("# Quantum Sealed Record Layer prototype key file\n");
    contents.push_str("type = \"private\"\n");
    contents.push_str(&format!("algorithm = \"{}\"\n", key.algorithm.as_str()));
    contents.push_str(&format!(
        "implementation = \"{}\"\n",
        key.implementation_label()
    ));
    contents.push_str(&format!("key_id = \"{}\"\n", key.key_id));
    contents.push_str(&format!("method_name = \"{}\"\n", key.method_name));
    if let Some(value) = &key.algorithm_version {
        contents.push_str(&format!("algorithm_version = \"{}\"\n", value));
    }
    if let Some(value) = &key.library_version {
        contents.push_str(&format!("library_version = \"{}\"\n", value));
    }
    contents.push_str(&format!(
        "public_key_fingerprint = \"{}\"\n",
        hex_encode(&key.public_key_fingerprint)
    ));
    contents.push_str(&format!(
        "public_key = \"{}\"\n",
        hex_encode(&key.public_key_bytes)
    ));
    contents.push_str(&format!(
        "secret_key = \"{}\"\n",
        hex_encode(&key.secret_key_bytes)
    ));
    contents.push_str(&format!("uses = {}\n", key.uses));
    contents
}

pub fn write_public_key(path: &Path, key: &PublicKey) -> Result<()> {
    let mut contents = String::new();
    contents.push_str("# Quantum Sealed Record Layer prototype key file\n");
    contents.push_str("type = \"public\"\n");
    contents.push_str(&format!("algorithm = \"{}\"\n", key.algorithm.as_str()));
    contents.push_str(&format!(
        "implementation = \"{}\"\n",
        key.implementation_label()
    ));
    contents.push_str(&format!("key_id = \"{}\"\n", key.key_id));
    contents.push_str(&format!("method_name = \"{}\"\n", key.method_name));
    if let Some(value) = &key.algorithm_version {
        contents.push_str(&format!("algorithm_version = \"{}\"\n", value));
    }
    if let Some(value) = &key.library_version {
        contents.push_str(&format!("library_version = \"{}\"\n", value));
    }
    contents.push_str(&format!(
        "public_key_fingerprint = \"{}\"\n",
        hex_encode(&key.fingerprint)
    ));
    contents.push_str(&format!(
        "public_key = \"{}\"\n",
        hex_encode(&key.public_key_bytes)
    ));
    write_string(path, &contents)
}

pub fn write_recipient_private_key(path: &Path, key: &KemPrivateKey) -> Result<()> {
    write_private_key_file(path, &recipient_private_key_contents(key), true)
}

pub fn write_new_recipient_private_key(path: &Path, key: &KemPrivateKey) -> Result<()> {
    write_private_key_file(path, &recipient_private_key_contents(key), false)
}

fn recipient_private_key_contents(key: &KemPrivateKey) -> String {
    let mut contents = String::new();
    contents.push_str("# Quantum Sealed Record Layer prototype recipient key file\n");
    contents.push_str("type = \"private\"\n");
    contents.push_str("usage = \"recipient\"\n");
    contents.push_str(&format!("algorithm = \"{}\"\n", key.algorithm.as_str()));
    contents.push_str(&format!(
        "implementation = \"{}\"\n",
        key.implementation_label()
    ));
    contents.push_str(&format!("key_id = \"{}\"\n", key.key_id));
    contents.push_str(&format!("method_name = \"{}\"\n", key.method_name));
    if let Some(value) = &key.algorithm_version {
        contents.push_str(&format!("algorithm_version = \"{}\"\n", value));
    }
    if let Some(value) = &key.library_version {
        contents.push_str(&format!("library_version = \"{}\"\n", value));
    }
    contents.push_str(&format!(
        "public_key_fingerprint = \"{}\"\n",
        hex_encode(&key.public_key_fingerprint)
    ));
    contents.push_str(&format!(
        "public_key = \"{}\"\n",
        hex_encode(&key.public_key_bytes)
    ));
    contents.push_str(&format!(
        "secret_key = \"{}\"\n",
        hex_encode(&key.secret_key_bytes)
    ));
    contents
}

fn write_private_key_file(path: &Path, contents: &str, allow_overwrite: bool) -> Result<()> {
    ensure_parent_dir(path)?;
    if allow_overwrite
        && let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(QsrlError::Usage(format!(
            "refusing to write private key through symlink {}",
            path.display()
        )));
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if allow_overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| QsrlError::io(format!("writing {}", path.display()), err))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        file.set_permissions(permissions).map_err(|err| {
            QsrlError::io(format!("setting permissions on {}", path.display()), err)
        })?;
    }
    file.write_all(contents.as_bytes())
        .map_err(|err| QsrlError::io(format!("writing {}", path.display()), err))
}

pub fn write_recipient_public_key(path: &Path, key: &KemPublicKey) -> Result<()> {
    let mut contents = String::new();
    contents.push_str("# Quantum Sealed Record Layer prototype recipient key file\n");
    contents.push_str("type = \"public\"\n");
    contents.push_str("usage = \"recipient\"\n");
    contents.push_str(&format!("algorithm = \"{}\"\n", key.algorithm.as_str()));
    contents.push_str(&format!(
        "implementation = \"{}\"\n",
        key.implementation_label()
    ));
    contents.push_str(&format!("key_id = \"{}\"\n", key.key_id));
    contents.push_str(&format!("method_name = \"{}\"\n", key.method_name));
    if let Some(value) = &key.algorithm_version {
        contents.push_str(&format!("algorithm_version = \"{}\"\n", value));
    }
    if let Some(value) = &key.library_version {
        contents.push_str(&format!("library_version = \"{}\"\n", value));
    }
    contents.push_str(&format!(
        "public_key_fingerprint = \"{}\"\n",
        hex_encode(&key.fingerprint)
    ));
    contents.push_str(&format!(
        "public_key = \"{}\"\n",
        hex_encode(&key.public_key_bytes)
    ));
    write_string(path, &contents)
}

pub fn load_private_key(path: &Path) -> Result<PrivateKey> {
    let map = parse_key_file(path)?;
    ensure_key_type(&map, "private")?;
    let implementation = KeyImplementation::from_label(required_field(&map, "implementation")?)?;
    let algorithm = required_field(&map, "algorithm")?.parse()?;
    let key_id = required_field(&map, "key_id")?.to_string();
    let method_name = determine_method_name(implementation, algorithm, &map)?.to_string();
    validate_method_name(implementation, algorithm, &method_name)?;
    let fingerprint = parse_fixed_32(required_field(&map, "public_key_fingerprint")?)?;
    let public_key_bytes = parse_public_key_blob(implementation, algorithm, &map)?;
    let secret_key_bytes = parse_private_key_blob(implementation, algorithm, &map)?;
    let algorithm_version = optional_field(&map, "algorithm_version").map(str::to_string);
    let library_version = optional_field(&map, "library_version").map(str::to_string);
    let uses = required_field(&map, "uses")?
        .parse::<u32>()
        .map_err(|_| QsrlError::Parse("invalid uses count in private key".into()))?;

    let derived = derive_fingerprint(implementation, algorithm, &method_name, &public_key_bytes)?;
    if derived != fingerprint {
        return Err(QsrlError::KeyRejected(
            "private key fingerprint did not match the encoded public key bytes".into(),
        ));
    }

    Ok(PrivateKey {
        algorithm,
        key_id,
        public_key_fingerprint: fingerprint,
        uses,
        implementation,
        method_name,
        algorithm_version,
        library_version,
        public_key_bytes,
        secret_key_bytes,
    })
}

pub fn load_public_key(path: &Path) -> Result<PublicKey> {
    let map = parse_key_file(path)?;
    ensure_key_type(&map, "public")?;
    let implementation = KeyImplementation::from_label(required_field(&map, "implementation")?)?;
    let algorithm = required_field(&map, "algorithm")?.parse()?;
    let key_id = required_field(&map, "key_id")?.to_string();
    let method_name = determine_method_name(implementation, algorithm, &map)?.to_string();
    validate_method_name(implementation, algorithm, &method_name)?;
    let fingerprint = parse_fixed_32(required_field(&map, "public_key_fingerprint")?)?;
    let public_key_bytes = parse_public_key_blob(implementation, algorithm, &map)?;
    let algorithm_version = optional_field(&map, "algorithm_version").map(str::to_string);
    let library_version = optional_field(&map, "library_version").map(str::to_string);

    let derived = derive_fingerprint(implementation, algorithm, &method_name, &public_key_bytes)?;
    if derived != fingerprint {
        return Err(QsrlError::KeyRejected(
            "public key fingerprint did not match the encoded public key bytes".into(),
        ));
    }

    Ok(PublicKey {
        algorithm,
        key_id,
        fingerprint,
        implementation,
        method_name,
        algorithm_version,
        library_version,
        public_key_bytes,
    })
}

pub fn load_recipient_private_key(path: &Path) -> Result<KemPrivateKey> {
    let map = parse_key_file(path)?;
    ensure_key_type(&map, "private")?;
    ensure_key_usage(&map, "recipient")?;
    let implementation = KeyImplementation::from_label(required_field(&map, "implementation")?)?;
    let algorithm = required_field(&map, "algorithm")?.parse()?;
    let key_id = required_field(&map, "key_id")?.to_string();
    let method_name = determine_kem_method_name(implementation, algorithm, &map)?.to_string();
    validate_kem_method_name(implementation, algorithm, &method_name)?;
    let fingerprint = parse_fixed_32(required_field(&map, "public_key_fingerprint")?)?;
    let public_key_bytes = parse_kem_public_key_blob(implementation, algorithm, &map)?;
    let secret_key_bytes = parse_kem_private_key_blob(implementation, algorithm, &map)?;
    let algorithm_version = optional_field(&map, "algorithm_version").map(str::to_string);
    let library_version = optional_field(&map, "library_version").map(str::to_string);

    let derived =
        derive_kem_fingerprint(implementation, algorithm, &method_name, &public_key_bytes)?;
    if derived != fingerprint {
        return Err(QsrlError::KeyRejected(
            "recipient private key fingerprint did not match the encoded public key bytes".into(),
        ));
    }

    Ok(KemPrivateKey {
        algorithm,
        key_id,
        public_key_fingerprint: fingerprint,
        implementation,
        method_name,
        algorithm_version,
        library_version,
        public_key_bytes,
        secret_key_bytes,
    })
}

pub fn load_recipient_public_key(path: &Path) -> Result<KemPublicKey> {
    let map = parse_key_file(path)?;
    ensure_key_type(&map, "public")?;
    ensure_key_usage(&map, "recipient")?;
    let implementation = KeyImplementation::from_label(required_field(&map, "implementation")?)?;
    let algorithm = required_field(&map, "algorithm")?.parse()?;
    let key_id = required_field(&map, "key_id")?.to_string();
    let method_name = determine_kem_method_name(implementation, algorithm, &map)?.to_string();
    validate_kem_method_name(implementation, algorithm, &method_name)?;
    let fingerprint = parse_fixed_32(required_field(&map, "public_key_fingerprint")?)?;
    let public_key_bytes = parse_kem_public_key_blob(implementation, algorithm, &map)?;
    let algorithm_version = optional_field(&map, "algorithm_version").map(str::to_string);
    let library_version = optional_field(&map, "library_version").map(str::to_string);

    let derived =
        derive_kem_fingerprint(implementation, algorithm, &method_name, &public_key_bytes)?;
    if derived != fingerprint {
        return Err(QsrlError::KeyRejected(
            "recipient public key fingerprint did not match the encoded public key bytes".into(),
        ));
    }

    Ok(KemPublicKey {
        algorithm,
        key_id,
        fingerprint,
        implementation,
        method_name,
        algorithm_version,
        library_version,
        public_key_bytes,
    })
}

pub fn message_digest(message: &[u8]) -> [u8; 32] {
    digest(message)
}

fn generate_stub_keypair(
    algorithm: SignatureAlgorithm,
    key_id: String,
) -> Result<(PrivateKey, PublicKey)> {
    let params = stub_params_for_algorithm(algorithm);
    let pair_count = params.challenge_bits * 2;
    let mut public_hashes = Vec::with_capacity(pair_count * 32);
    let mut secret_values = Vec::with_capacity(pair_count * params.secret_size);

    for index in 0..pair_count {
        let secret = read_random_bytes(params.secret_size)?;
        let public_hash = public_value_hash(algorithm, index, &secret);
        public_hashes.extend_from_slice(&public_hash);
        secret_values.extend_from_slice(&secret);
    }

    let method_name = stub_method_name(algorithm).to_string();
    let fingerprint = derive_stub_fingerprint(algorithm, &public_hashes);
    let private_key = PrivateKey {
        algorithm,
        key_id: key_id.clone(),
        public_key_fingerprint: fingerprint,
        uses: 0,
        implementation: KeyImplementation::StubLamportV1,
        method_name: method_name.clone(),
        algorithm_version: Some(STUB_IMPLEMENTATION_LABEL.into()),
        library_version: None,
        public_key_bytes: public_hashes.clone(),
        secret_key_bytes: secret_values,
    };
    let public_key = PublicKey {
        algorithm,
        key_id,
        fingerprint,
        implementation: KeyImplementation::StubLamportV1,
        method_name,
        algorithm_version: Some(STUB_IMPLEMENTATION_LABEL.into()),
        library_version: None,
        public_key_bytes: public_hashes,
    };
    Ok((private_key, public_key))
}

fn sign_stub_message(private_key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>> {
    validate_method_name(
        private_key.implementation,
        private_key.algorithm,
        &private_key.method_name,
    )?;
    let params = stub_params_for_algorithm(private_key.algorithm);
    let challenge = challenge_bytes(private_key.algorithm, message);
    if challenge.len() * 8 != params.challenge_bits {
        return Err(QsrlError::KeyRejected(
            "private key challenge width does not match algorithm".into(),
        ));
    }
    let expected_secret_len = params.challenge_bits * 2 * params.secret_size;
    if private_key.secret_key_bytes.len() != expected_secret_len {
        return Err(QsrlError::KeyRejected(format!(
            "stub secret key length {} did not match expected {expected_secret_len}",
            private_key.secret_key_bytes.len()
        )));
    }

    let mut signature = Vec::with_capacity(params.challenge_bits * params.secret_size);
    for bit_index in 0..params.challenge_bits {
        let bit = challenge_bit(&challenge, bit_index);
        let source_index = bit_index * 2 + bit;
        let start = source_index * params.secret_size;
        let end = start + params.secret_size;
        signature.extend_from_slice(&private_key.secret_key_bytes[start..end]);
    }
    Ok(signature)
}

fn verify_stub_signature(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    validate_method_name(
        public_key.implementation,
        public_key.algorithm,
        &public_key.method_name,
    )?;
    let params = stub_params_for_algorithm(public_key.algorithm);
    let challenge = challenge_bytes(public_key.algorithm, message);
    if challenge.len() * 8 != params.challenge_bits {
        return Err(QsrlError::SignatureVerificationFailed(
            "challenge width does not match public key".into(),
        ));
    }
    let expected_public_len = params.challenge_bits * 2 * 32;
    if public_key.public_key_bytes.len() != expected_public_len {
        return Err(QsrlError::KeyRejected(format!(
            "stub public key length {} did not match expected {expected_public_len}",
            public_key.public_key_bytes.len()
        )));
    }
    let expected_signature_len = params.challenge_bits * params.secret_size;
    if signature.len() != expected_signature_len {
        return Err(QsrlError::SignatureVerificationFailed(format!(
            "signature length {} did not match expected {expected_signature_len}",
            signature.len()
        )));
    }

    for bit_index in 0..params.challenge_bits {
        let bit = challenge_bit(&challenge, bit_index);
        let source_index = bit_index * 2 + bit;
        let signature_start = bit_index * params.secret_size;
        let signature_end = signature_start + params.secret_size;
        let revealed = &signature[signature_start..signature_end];
        let candidate_hash = public_value_hash(public_key.algorithm, source_index, revealed);
        let public_start = source_index * 32;
        let public_end = public_start + 32;
        if candidate_hash[..] != public_key.public_key_bytes[public_start..public_end] {
            return Err(QsrlError::SignatureVerificationFailed(format!(
                "signature mismatch at challenge position {bit_index}"
            )));
        }
    }

    Ok(())
}

fn generate_liboqs_kem_keypair(
    algorithm: KemAlgorithm,
    key_id: String,
) -> Result<(KemPrivateKey, KemPublicKey)> {
    #[cfg(feature = "liboqs-backend")]
    {
        let method_name = liboqs_kem_method_name_for_algorithm(algorithm).to_string();
        let kem = liboqs::KemScheme::new(&method_name)?;
        let (public_key_bytes, secret_key_bytes) = kem.keypair()?;
        let fingerprint = derive_liboqs_kem_fingerprint(algorithm, &method_name, &public_key_bytes);
        let algorithm_version = Some(kem.algorithm_version());
        let library_version = Some(kem.library_version());
        let private_key = KemPrivateKey {
            algorithm,
            key_id: key_id.clone(),
            public_key_fingerprint: fingerprint,
            implementation: KeyImplementation::LiboqsSystemV1,
            method_name: method_name.clone(),
            algorithm_version: algorithm_version.clone(),
            library_version: library_version.clone(),
            public_key_bytes: public_key_bytes.clone(),
            secret_key_bytes,
        };
        let public_key = KemPublicKey {
            algorithm,
            key_id,
            fingerprint,
            implementation: KeyImplementation::LiboqsSystemV1,
            method_name,
            algorithm_version,
            library_version,
            public_key_bytes,
        };
        Ok((private_key, public_key))
    }
    #[cfg(not(feature = "liboqs-backend"))]
    {
        let _ = algorithm;
        let _ = key_id;
        Err(QsrlError::UnsupportedFeature(
            "this build does not include the liboqs backend".into(),
        ))
    }
}

fn generate_liboqs_keypair(
    algorithm: SignatureAlgorithm,
    key_id: String,
) -> Result<(PrivateKey, PublicKey)> {
    #[cfg(feature = "liboqs-backend")]
    {
        let method_name = liboqs_method_name_for_algorithm(algorithm).to_string();
        let sig = liboqs::SignatureScheme::new(&method_name)?;
        let (public_key_bytes, secret_key_bytes) = sig.keypair()?;
        let fingerprint = derive_liboqs_fingerprint(algorithm, &method_name, &public_key_bytes);
        let algorithm_version = Some(sig.algorithm_version());
        let library_version = Some(sig.library_version());
        let private_key = PrivateKey {
            algorithm,
            key_id: key_id.clone(),
            public_key_fingerprint: fingerprint,
            uses: 0,
            implementation: KeyImplementation::LiboqsSystemV1,
            method_name: method_name.clone(),
            algorithm_version: algorithm_version.clone(),
            library_version: library_version.clone(),
            public_key_bytes: public_key_bytes.clone(),
            secret_key_bytes,
        };
        let public_key = PublicKey {
            algorithm,
            key_id,
            fingerprint,
            implementation: KeyImplementation::LiboqsSystemV1,
            method_name,
            algorithm_version,
            library_version,
            public_key_bytes,
        };
        Ok((private_key, public_key))
    }
    #[cfg(not(feature = "liboqs-backend"))]
    {
        let _ = algorithm;
        let _ = key_id;
        Err(QsrlError::UnsupportedFeature(
            "this build does not include the liboqs backend".into(),
        ))
    }
}

fn sign_liboqs_message(private_key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "liboqs-backend")]
    {
        validate_method_name(
            private_key.implementation,
            private_key.algorithm,
            &private_key.method_name,
        )?;
        let sig = liboqs::SignatureScheme::new(&private_key.method_name)?;
        sig.sign(message, &private_key.secret_key_bytes)
    }
    #[cfg(not(feature = "liboqs-backend"))]
    {
        let _ = private_key;
        let _ = message;
        Err(QsrlError::UnsupportedFeature(
            "this build cannot sign liboqs-backed keys; rebuild with --features liboqs-backend"
                .into(),
        ))
    }
}

fn verify_liboqs_signature(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    #[cfg(feature = "liboqs-backend")]
    {
        validate_method_name(
            public_key.implementation,
            public_key.algorithm,
            &public_key.method_name,
        )?;
        let sig = liboqs::SignatureScheme::new(&public_key.method_name)?;
        sig.verify(message, signature, &public_key.public_key_bytes)
    }
    #[cfg(not(feature = "liboqs-backend"))]
    {
        let _ = public_key;
        let _ = message;
        let _ = signature;
        Err(QsrlError::UnsupportedFeature(
            "this build cannot verify liboqs-backed signatures; rebuild with --features liboqs-backend"
                .into(),
        ))
    }
}

fn wrap_archive_key_liboqs(
    public_key: &KemPublicKey,
    archive_key: &[u8],
) -> Result<RecipientRecord> {
    #[cfg(feature = "liboqs-backend")]
    {
        validate_kem_method_name(
            public_key.implementation,
            public_key.algorithm,
            &public_key.method_name,
        )?;
        let kem = liboqs::KemScheme::new(&public_key.method_name)?;
        let (kem_ciphertext, shared_secret) = kem.encaps(&public_key.public_key_bytes)?;
        let wrap_key = derive_wrap_key(&shared_secret, &public_key.fingerprint);
        let wrap_nonce = read_random_bytes(AEAD_NONCE_LEN)?;
        let wrap_aad = recipient_wrap_aad(&public_key.fingerprint, &kem_ciphertext);
        let (wrapped_key, wrap_tag) = encrypt_aead(&wrap_key, &wrap_nonce, &wrap_aad, archive_key)?;
        Ok(RecipientRecord {
            implementation: public_key.implementation_code(),
            public_key_fingerprint: public_key.fingerprint,
            kem_ciphertext,
            wrap_nonce,
            wrapped_key,
            wrap_tag,
        })
    }
    #[cfg(not(feature = "liboqs-backend"))]
    {
        let _ = public_key;
        let _ = archive_key;
        Err(QsrlError::UnsupportedFeature(
            "this build does not include the liboqs backend".into(),
        ))
    }
}

fn unwrap_archive_key_liboqs(
    private_key: &KemPrivateKey,
    record: &RecipientRecord,
) -> Result<Vec<u8>> {
    #[cfg(feature = "liboqs-backend")]
    {
        if record.implementation != private_key.implementation_code() {
            return Err(QsrlError::KeyRejected(
                "recipient record backend does not match the provided private key".into(),
            ));
        }
        if record.public_key_fingerprint != private_key.public_key_fingerprint {
            return Err(QsrlError::KeyRejected(
                "recipient private key does not match any recipient record in this archive".into(),
            ));
        }
        validate_kem_method_name(
            private_key.implementation,
            private_key.algorithm,
            &private_key.method_name,
        )?;
        let kem = liboqs::KemScheme::new(&private_key.method_name)?;
        let shared_secret = kem.decaps(&record.kem_ciphertext, &private_key.secret_key_bytes)?;
        let wrap_key = derive_wrap_key(&shared_secret, &private_key.public_key_fingerprint);
        let wrap_aad =
            recipient_wrap_aad(&private_key.public_key_fingerprint, &record.kem_ciphertext);
        decrypt_aead(
            &wrap_key,
            &record.wrap_nonce,
            &wrap_aad,
            &record.wrapped_key,
            &record.wrap_tag,
        )
        .map_err(|error| match error {
            QsrlError::DataCorruption(_) => QsrlError::KeyRejected(
                "recipient private key could not unwrap the archive key for this record".into(),
            ),
            other => other,
        })
    }
    #[cfg(not(feature = "liboqs-backend"))]
    {
        let _ = private_key;
        let _ = record;
        Err(QsrlError::UnsupportedFeature(
            "this build does not include the liboqs backend".into(),
        ))
    }
}

#[cfg(feature = "liboqs-backend")]
fn derive_wrap_key(shared_secret: &[u8], fingerprint: &[u8; 32]) -> [u8; 32] {
    digest_parts(&[b"QSRL-RECIPIENT-WRAP-KEY", shared_secret, fingerprint])
}

#[cfg(feature = "liboqs-backend")]
fn recipient_wrap_aad(fingerprint: &[u8; 32], kem_ciphertext: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(24 + fingerprint.len() + kem_ciphertext.len());
    aad.extend_from_slice(b"QSRL-RECIPIENT-WRAP-AAD");
    aad.extend_from_slice(fingerprint);
    aad.extend_from_slice(kem_ciphertext);
    aad
}

fn derive_fingerprint(
    implementation: KeyImplementation,
    algorithm: SignatureAlgorithm,
    method_name: &str,
    public_key_bytes: &[u8],
) -> Result<[u8; 32]> {
    Ok(match implementation {
        KeyImplementation::StubLamportV1 => derive_stub_fingerprint(algorithm, public_key_bytes),
        KeyImplementation::LiboqsSystemV1 => {
            derive_liboqs_fingerprint(algorithm, method_name, public_key_bytes)
        }
    })
}

fn derive_stub_fingerprint(algorithm: SignatureAlgorithm, public_key_bytes: &[u8]) -> [u8; 32] {
    digest_parts(&[
        b"QSRL-STUB-LAMPORT-FINGERPRINT",
        algorithm.as_str().as_bytes(),
        public_key_bytes,
    ])
}

fn derive_liboqs_fingerprint(
    algorithm: SignatureAlgorithm,
    method_name: &str,
    public_key_bytes: &[u8],
) -> [u8; 32] {
    digest_parts(&[
        b"QSRL-LIBOQS-FINGERPRINT",
        algorithm.as_str().as_bytes(),
        method_name.as_bytes(),
        public_key_bytes,
    ])
}

fn derive_kem_fingerprint(
    implementation: KeyImplementation,
    algorithm: KemAlgorithm,
    method_name: &str,
    public_key_bytes: &[u8],
) -> Result<[u8; 32]> {
    Ok(match implementation {
        KeyImplementation::LiboqsSystemV1 => {
            derive_liboqs_kem_fingerprint(algorithm, method_name, public_key_bytes)
        }
        KeyImplementation::StubLamportV1 => {
            return Err(QsrlError::UnsupportedFeature(
                "recipient encryption is not available with the stub backend".into(),
            ));
        }
    })
}

fn derive_liboqs_kem_fingerprint(
    algorithm: KemAlgorithm,
    method_name: &str,
    public_key_bytes: &[u8],
) -> [u8; 32] {
    digest_parts(&[
        b"QSRL-LIBOQS-KEM-FINGERPRINT",
        algorithm.as_str().as_bytes(),
        method_name.as_bytes(),
        public_key_bytes,
    ])
}

fn parse_key_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let contents = read_string(path)?;
    let mut fields = BTreeMap::new();
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

fn required_field<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    fields
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| QsrlError::Parse(format!("key file missing '{name}'")))
}

fn optional_field<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    fields.get(name).map(String::as_str)
}

fn ensure_key_type(fields: &BTreeMap<String, String>, expected_type: &str) -> Result<()> {
    let actual = required_field(fields, "type")?;
    if actual != expected_type {
        return Err(QsrlError::KeyRejected(format!(
            "expected a {expected_type} key file but found '{actual}'"
        )));
    }
    Ok(())
}

fn ensure_key_usage(fields: &BTreeMap<String, String>, expected_usage: &str) -> Result<()> {
    let actual = required_field(fields, "usage")?;
    if actual != expected_usage {
        return Err(QsrlError::KeyRejected(format!(
            "expected a {expected_usage} key file but found usage '{actual}'"
        )));
    }
    Ok(())
}

fn determine_method_name(
    implementation: KeyImplementation,
    algorithm: SignatureAlgorithm,
    fields: &BTreeMap<String, String>,
) -> Result<&str> {
    if let Some(value) = optional_field(fields, "method_name") {
        return Ok(value);
    }
    match implementation {
        KeyImplementation::StubLamportV1 => Ok(stub_method_name(algorithm)),
        KeyImplementation::LiboqsSystemV1 => Err(QsrlError::Parse(
            "liboqs-backed keys must include a method_name field".into(),
        )),
    }
}

fn determine_kem_method_name(
    implementation: KeyImplementation,
    algorithm: KemAlgorithm,
    fields: &BTreeMap<String, String>,
) -> Result<&str> {
    if let Some(value) = optional_field(fields, "method_name") {
        return Ok(value);
    }
    match implementation {
        KeyImplementation::LiboqsSystemV1 => Ok(liboqs_kem_method_name_for_algorithm(algorithm)),
        KeyImplementation::StubLamportV1 => Err(QsrlError::Parse(
            "recipient keys do not support the stub backend".into(),
        )),
    }
}

fn validate_method_name(
    implementation: KeyImplementation,
    algorithm: SignatureAlgorithm,
    method_name: &str,
) -> Result<()> {
    match implementation {
        KeyImplementation::StubLamportV1 => {
            if method_name == stub_method_name(algorithm) {
                Ok(())
            } else {
                Err(QsrlError::KeyRejected(format!(
                    "stub key method_name '{method_name}' did not match {}",
                    stub_method_name(algorithm)
                )))
            }
        }
        KeyImplementation::LiboqsSystemV1 => match algorithm {
            SignatureAlgorithm::MlDsa if method_name.starts_with("ML-DSA-") => Ok(()),
            SignatureAlgorithm::SlhDsa if method_name.starts_with("SLH_DSA_") => Ok(()),
            SignatureAlgorithm::MlDsa | SignatureAlgorithm::SlhDsa => {
                Err(QsrlError::KeyRejected(format!(
                    "method_name '{method_name}' does not match algorithm family {}",
                    algorithm.as_str()
                )))
            }
        },
    }
}

fn validate_kem_method_name(
    implementation: KeyImplementation,
    algorithm: KemAlgorithm,
    method_name: &str,
) -> Result<()> {
    match implementation {
        KeyImplementation::LiboqsSystemV1 => match algorithm {
            KemAlgorithm::MlKem if method_name.starts_with("ML-KEM-") => Ok(()),
            KemAlgorithm::MlKem => Err(QsrlError::KeyRejected(format!(
                "method_name '{method_name}' does not match algorithm family {}",
                algorithm.as_str()
            ))),
        },
        KeyImplementation::StubLamportV1 => Err(QsrlError::KeyRejected(
            "recipient encryption is not available with the stub backend".into(),
        )),
    }
}

fn parse_public_key_blob(
    implementation: KeyImplementation,
    algorithm: SignatureAlgorithm,
    fields: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let bytes = if let Some(value) = optional_field(fields, "public_key") {
        hex_decode(value)?
    } else if implementation == KeyImplementation::StubLamportV1 {
        hex_decode(required_field(fields, "public_hashes")?)?
    } else {
        return Err(QsrlError::Parse("key file missing public_key field".into()));
    };
    validate_key_blob_lengths(implementation, algorithm, &bytes, false)?;
    Ok(bytes)
}

fn parse_private_key_blob(
    implementation: KeyImplementation,
    algorithm: SignatureAlgorithm,
    fields: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let bytes = if let Some(value) = optional_field(fields, "secret_key") {
        hex_decode(value)?
    } else if implementation == KeyImplementation::StubLamportV1 {
        hex_decode(required_field(fields, "secret_values")?)?
    } else {
        return Err(QsrlError::Parse(
            "private key file missing secret_key field".into(),
        ));
    };
    validate_key_blob_lengths(implementation, algorithm, &bytes, true)?;
    Ok(bytes)
}

fn parse_kem_public_key_blob(
    implementation: KeyImplementation,
    algorithm: KemAlgorithm,
    fields: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let bytes = hex_decode(required_field(fields, "public_key")?)?;
    validate_kem_key_blob_lengths(implementation, algorithm, &bytes, false)?;
    Ok(bytes)
}

fn parse_kem_private_key_blob(
    implementation: KeyImplementation,
    algorithm: KemAlgorithm,
    fields: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let bytes = hex_decode(required_field(fields, "secret_key")?)?;
    validate_kem_key_blob_lengths(implementation, algorithm, &bytes, true)?;
    Ok(bytes)
}

fn validate_key_blob_lengths(
    implementation: KeyImplementation,
    algorithm: SignatureAlgorithm,
    bytes: &[u8],
    private: bool,
) -> Result<()> {
    match implementation {
        KeyImplementation::StubLamportV1 => {
            let params = stub_params_for_algorithm(algorithm);
            let expected_len = if private {
                params.challenge_bits * 2 * params.secret_size
            } else {
                params.challenge_bits * 2 * 32
            };
            if bytes.len() != expected_len {
                return Err(QsrlError::Parse(format!(
                    "stub {} key length {} did not match expected {expected_len}",
                    if private { "private" } else { "public" },
                    bytes.len()
                )));
            }
            Ok(())
        }
        KeyImplementation::LiboqsSystemV1 => {
            if bytes.is_empty() {
                return Err(QsrlError::Parse(format!(
                    "liboqs {} key bytes must not be empty",
                    if private { "private" } else { "public" }
                )));
            }
            Ok(())
        }
    }
}

fn validate_kem_key_blob_lengths(
    implementation: KeyImplementation,
    algorithm: KemAlgorithm,
    bytes: &[u8],
    private: bool,
) -> Result<()> {
    match implementation {
        KeyImplementation::LiboqsSystemV1 => {
            let _ = algorithm;
            if bytes.is_empty() {
                return Err(QsrlError::Parse(format!(
                    "liboqs {} recipient key bytes must not be empty",
                    if private { "private" } else { "public" }
                )));
            }
            Ok(())
        }
        KeyImplementation::StubLamportV1 => Err(QsrlError::Parse(
            "recipient encryption is not available with the stub backend".into(),
        )),
    }
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

fn stub_params_for_algorithm(algorithm: SignatureAlgorithm) -> StubParams {
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

fn stub_method_name(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::MlDsa => STUB_METHOD_NAME_ML_DSA,
        SignatureAlgorithm::SlhDsa => STUB_METHOD_NAME_SLH_DSA,
    }
}

#[cfg(feature = "liboqs-backend")]
fn liboqs_method_name_for_algorithm(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::MlDsa => LIBOQS_METHOD_NAME_ML_DSA,
        SignatureAlgorithm::SlhDsa => LIBOQS_METHOD_NAME_SLH_DSA,
    }
}

#[cfg(feature = "liboqs-backend")]
fn liboqs_kem_method_name_for_algorithm(algorithm: KemAlgorithm) -> &'static str {
    match algorithm {
        KemAlgorithm::MlKem => LIBOQS_METHOD_NAME_ML_KEM,
    }
}

#[cfg(not(feature = "liboqs-backend"))]
fn liboqs_kem_method_name_for_algorithm(algorithm: KemAlgorithm) -> &'static str {
    match algorithm {
        KemAlgorithm::MlKem => "ML-KEM-768",
    }
}

#[cfg(feature = "liboqs-backend")]
mod liboqs {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int};
    use std::ptr::NonNull;
    use std::sync::Once;

    use crate::error::{QsrlError, Result};

    const OQS_SUCCESS: c_int = 0;

    #[repr(C)]
    struct RawSig {
        method_name: *const c_char,
        alg_version: *const c_char,
        claimed_nist_level: u8,
        euf_cma: u8,
        suf_cma: u8,
        sig_with_ctx_support: u8,
        length_public_key: usize,
        length_secret_key: usize,
        length_signature: usize,
        keypair: Option<unsafe extern "C" fn(*mut u8, *mut u8) -> c_int>,
        sign:
            Option<unsafe extern "C" fn(*mut u8, *mut usize, *const u8, usize, *const u8) -> c_int>,
        sign_with_ctx_str: Option<
            unsafe extern "C" fn(
                *mut u8,
                *mut usize,
                *const u8,
                usize,
                *const u8,
                usize,
                *const u8,
            ) -> c_int,
        >,
        verify:
            Option<unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8) -> c_int>,
        verify_with_ctx_str: Option<
            unsafe extern "C" fn(
                *const u8,
                usize,
                *const u8,
                usize,
                *const u8,
                usize,
                *const u8,
            ) -> c_int,
        >,
    }

    #[repr(C)]
    struct RawKem {
        method_name: *const c_char,
        alg_version: *const c_char,
        claimed_nist_level: u8,
        ind_cca: u8,
        length_public_key: usize,
        length_secret_key: usize,
        length_ciphertext: usize,
        length_shared_secret: usize,
        length_keypair_seed: usize,
        length_encaps_seed: usize,
        keypair_derand: Option<unsafe extern "C" fn(*mut u8, *mut u8, *const u8) -> c_int>,
        keypair: Option<unsafe extern "C" fn(*mut u8, *mut u8) -> c_int>,
        encaps_derand:
            Option<unsafe extern "C" fn(*mut u8, *mut u8, *const u8, *const u8) -> c_int>,
        encaps: Option<unsafe extern "C" fn(*mut u8, *mut u8, *const u8) -> c_int>,
        decaps: Option<unsafe extern "C" fn(*mut u8, *const u8, *const u8) -> c_int>,
    }

    unsafe extern "C" {
        fn OQS_init();
        fn OQS_version() -> *const c_char;
        fn OQS_SIG_alg_is_enabled(method_name: *const c_char) -> c_int;
        fn OQS_SIG_new(method_name: *const c_char) -> *mut RawSig;
        fn OQS_SIG_free(sig: *mut RawSig);
        fn OQS_SIG_keypair(sig: *const RawSig, public_key: *mut u8, secret_key: *mut u8) -> c_int;
        fn OQS_SIG_sign(
            sig: *const RawSig,
            signature: *mut u8,
            signature_len: *mut usize,
            message: *const u8,
            message_len: usize,
            secret_key: *const u8,
        ) -> c_int;
        fn OQS_SIG_verify(
            sig: *const RawSig,
            message: *const u8,
            message_len: usize,
            signature: *const u8,
            signature_len: usize,
            public_key: *const u8,
        ) -> c_int;
        fn OQS_KEM_alg_is_enabled(method_name: *const c_char) -> c_int;
        fn OQS_KEM_new(method_name: *const c_char) -> *mut RawKem;
        fn OQS_KEM_free(kem: *mut RawKem);
        fn OQS_KEM_keypair(kem: *const RawKem, public_key: *mut u8, secret_key: *mut u8) -> c_int;
        fn OQS_KEM_encaps(
            kem: *const RawKem,
            ciphertext: *mut u8,
            shared_secret: *mut u8,
            public_key: *const u8,
        ) -> c_int;
        fn OQS_KEM_decaps(
            kem: *const RawKem,
            shared_secret: *mut u8,
            ciphertext: *const u8,
            secret_key: *const u8,
        ) -> c_int;
    }

    static INIT: Once = Once::new();

    pub struct SignatureScheme {
        sig: NonNull<RawSig>,
    }

    pub struct KemScheme {
        kem: NonNull<RawKem>,
    }

    impl SignatureScheme {
        pub fn new(method_name: &str) -> Result<Self> {
            init_once();
            let method_name_c = CString::new(method_name)
                .map_err(|_| QsrlError::Parse("liboqs method name contained a NUL byte".into()))?;
            let enabled = unsafe { OQS_SIG_alg_is_enabled(method_name_c.as_ptr()) };
            if enabled != 1 {
                return Err(QsrlError::UnsupportedFeature(format!(
                    "liboqs does not have signature method '{method_name}' enabled"
                )));
            }
            let sig = unsafe { OQS_SIG_new(method_name_c.as_ptr()) };
            let sig = NonNull::new(sig).ok_or_else(|| {
                QsrlError::UnsupportedFeature(format!(
                    "liboqs could not construct signature method '{method_name}'"
                ))
            })?;
            Ok(Self { sig })
        }

        pub fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
            let sig = self.raw();
            let mut public_key = vec![0u8; sig.length_public_key];
            let mut secret_key = vec![0u8; sig.length_secret_key];
            oqs_result(
                unsafe {
                    OQS_SIG_keypair(
                        self.sig.as_ptr(),
                        public_key.as_mut_ptr(),
                        secret_key.as_mut_ptr(),
                    )
                },
                "generating liboqs keypair",
            )?;
            Ok((public_key, secret_key))
        }

        pub fn sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
            let sig = self.raw();
            if secret_key.len() != sig.length_secret_key {
                return Err(QsrlError::KeyRejected(format!(
                    "secret key length {} did not match liboqs method expectation {}",
                    secret_key.len(),
                    sig.length_secret_key
                )));
            }

            let mut signature = vec![0u8; sig.length_signature];
            let mut signature_len = 0usize;
            oqs_result(
                unsafe {
                    OQS_SIG_sign(
                        self.sig.as_ptr(),
                        signature.as_mut_ptr(),
                        &mut signature_len,
                        message.as_ptr(),
                        message.len(),
                        secret_key.as_ptr(),
                    )
                },
                "signing message with liboqs",
            )?;
            signature.truncate(signature_len);
            Ok(signature)
        }

        pub fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
            let sig = self.raw();
            if public_key.len() != sig.length_public_key {
                return Err(QsrlError::KeyRejected(format!(
                    "public key length {} did not match liboqs method expectation {}",
                    public_key.len(),
                    sig.length_public_key
                )));
            }
            oqs_result(
                unsafe {
                    OQS_SIG_verify(
                        self.sig.as_ptr(),
                        message.as_ptr(),
                        message.len(),
                        signature.as_ptr(),
                        signature.len(),
                        public_key.as_ptr(),
                    )
                },
                "verifying liboqs signature",
            )
            .map_err(|_| {
                QsrlError::SignatureVerificationFailed(
                    "liboqs rejected the signature for this public key".into(),
                )
            })
        }

        pub fn algorithm_version(&self) -> String {
            c_string(self.raw().alg_version)
        }

        pub fn library_version(&self) -> String {
            unsafe { c_string(OQS_version()) }
        }
    }

    impl KemScheme {
        pub fn new(method_name: &str) -> Result<Self> {
            init_once();
            let method_name_c = CString::new(method_name)
                .map_err(|_| QsrlError::Parse("liboqs method name contained a NUL byte".into()))?;
            let enabled = unsafe { OQS_KEM_alg_is_enabled(method_name_c.as_ptr()) };
            if enabled != 1 {
                return Err(QsrlError::UnsupportedFeature(format!(
                    "liboqs does not have KEM method '{method_name}' enabled"
                )));
            }
            let kem = unsafe { OQS_KEM_new(method_name_c.as_ptr()) };
            let kem = NonNull::new(kem).ok_or_else(|| {
                QsrlError::UnsupportedFeature(format!(
                    "liboqs could not construct KEM method '{method_name}'"
                ))
            })?;
            Ok(Self { kem })
        }

        pub fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
            let kem = self.raw();
            let mut public_key = vec![0u8; kem.length_public_key];
            let mut secret_key = vec![0u8; kem.length_secret_key];
            oqs_result(
                unsafe {
                    OQS_KEM_keypair(
                        self.kem.as_ptr(),
                        public_key.as_mut_ptr(),
                        secret_key.as_mut_ptr(),
                    )
                },
                "generating liboqs recipient keypair",
            )?;
            Ok((public_key, secret_key))
        }

        pub fn encaps(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            let kem = self.raw();
            if public_key.len() != kem.length_public_key {
                return Err(QsrlError::KeyRejected(format!(
                    "public key length {} did not match liboqs KEM expectation {}",
                    public_key.len(),
                    kem.length_public_key
                )));
            }
            let mut ciphertext = vec![0u8; kem.length_ciphertext];
            let mut shared_secret = vec![0u8; kem.length_shared_secret];
            oqs_result(
                unsafe {
                    OQS_KEM_encaps(
                        self.kem.as_ptr(),
                        ciphertext.as_mut_ptr(),
                        shared_secret.as_mut_ptr(),
                        public_key.as_ptr(),
                    )
                },
                "encapsulating archive key for recipient",
            )?;
            Ok((ciphertext, shared_secret))
        }

        pub fn decaps(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
            let kem = self.raw();
            if ciphertext.len() != kem.length_ciphertext {
                return Err(QsrlError::KeyRejected(format!(
                    "recipient ciphertext length {} did not match liboqs KEM expectation {}",
                    ciphertext.len(),
                    kem.length_ciphertext
                )));
            }
            if secret_key.len() != kem.length_secret_key {
                return Err(QsrlError::KeyRejected(format!(
                    "secret key length {} did not match liboqs KEM expectation {}",
                    secret_key.len(),
                    kem.length_secret_key
                )));
            }
            let mut shared_secret = vec![0u8; kem.length_shared_secret];
            oqs_result(
                unsafe {
                    OQS_KEM_decaps(
                        self.kem.as_ptr(),
                        shared_secret.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        secret_key.as_ptr(),
                    )
                },
                "decapsulating archive key for recipient",
            )
            .map_err(|_| {
                QsrlError::KeyRejected(
                    "recipient private key could not decapsulate this archive record".into(),
                )
            })?;
            Ok(shared_secret)
        }

        pub fn algorithm_version(&self) -> String {
            c_string(self.raw().alg_version)
        }

        pub fn library_version(&self) -> String {
            unsafe { c_string(OQS_version()) }
        }
    }

    impl Drop for SignatureScheme {
        fn drop(&mut self) {
            unsafe { OQS_SIG_free(self.sig.as_ptr()) };
        }
    }

    impl Drop for KemScheme {
        fn drop(&mut self) {
            unsafe { OQS_KEM_free(self.kem.as_ptr()) };
        }
    }

    impl SignatureScheme {
        fn raw(&self) -> &RawSig {
            unsafe { self.sig.as_ref() }
        }
    }

    impl KemScheme {
        fn raw(&self) -> &RawKem {
            unsafe { self.kem.as_ref() }
        }
    }

    fn init_once() {
        INIT.call_once(|| unsafe { OQS_init() });
    }

    fn oqs_result(status: c_int, context: &str) -> Result<()> {
        if status == OQS_SUCCESS {
            Ok(())
        } else {
            Err(QsrlError::UnsupportedFeature(context.into()))
        }
    }

    fn c_string(ptr: *const c_char) -> String {
        if ptr.is_null() {
            return String::new();
        }
        unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .unwrap_or_default()
            .to_string()
    }
}

#[cfg(feature = "liboqs-backend")]
mod openssl_aead {
    use std::os::raw::{c_int, c_void};
    use std::ptr::NonNull;

    use crate::crypto::{AEAD_NONCE_LEN, AEAD_TAG_LEN, ARCHIVE_KEY_LEN};
    use crate::error::{QsrlError, Result};

    const EVP_CTRL_GCM_SET_IVLEN: c_int = 0x9;
    const EVP_CTRL_GCM_GET_TAG: c_int = 0x10;
    const EVP_CTRL_GCM_SET_TAG: c_int = 0x11;

    #[repr(C)]
    struct EvpCipher {
        _private: [u8; 0],
    }

    #[repr(C)]
    struct EvpCipherCtx {
        _private: [u8; 0],
    }

    unsafe extern "C" {
        fn EVP_aes_256_gcm() -> *const EvpCipher;
        fn EVP_CIPHER_CTX_new() -> *mut EvpCipherCtx;
        fn EVP_CIPHER_CTX_free(ctx: *mut EvpCipherCtx);
        fn EVP_EncryptInit_ex(
            ctx: *mut EvpCipherCtx,
            cipher: *const EvpCipher,
            engine: *mut c_void,
            key: *const u8,
            iv: *const u8,
        ) -> c_int;
        fn EVP_EncryptUpdate(
            ctx: *mut EvpCipherCtx,
            out: *mut u8,
            out_len: *mut c_int,
            in_: *const u8,
            in_len: c_int,
        ) -> c_int;
        fn EVP_EncryptFinal_ex(ctx: *mut EvpCipherCtx, out: *mut u8, out_len: *mut c_int) -> c_int;
        fn EVP_DecryptInit_ex(
            ctx: *mut EvpCipherCtx,
            cipher: *const EvpCipher,
            engine: *mut c_void,
            key: *const u8,
            iv: *const u8,
        ) -> c_int;
        fn EVP_DecryptUpdate(
            ctx: *mut EvpCipherCtx,
            out: *mut u8,
            out_len: *mut c_int,
            in_: *const u8,
            in_len: c_int,
        ) -> c_int;
        fn EVP_DecryptFinal_ex(ctx: *mut EvpCipherCtx, outm: *mut u8, out_len: *mut c_int)
        -> c_int;
        fn EVP_CIPHER_CTX_ctrl(
            ctx: *mut EvpCipherCtx,
            type_: c_int,
            arg: c_int,
            ptr: *mut c_void,
        ) -> c_int;
    }

    pub fn encrypt_aes_256_gcm(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        validate_lengths(key, nonce)?;
        let ctx = CipherCtx::new()?;
        let cipher = unsafe { EVP_aes_256_gcm() };
        if cipher.is_null() {
            return Err(QsrlError::UnsupportedFeature(
                "OpenSSL AES-256-GCM cipher is unavailable".into(),
            ));
        }

        openssl_ok(
            unsafe {
                EVP_EncryptInit_ex(
                    ctx.as_ptr(),
                    cipher,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            "initializing AES-256-GCM",
        )?;
        openssl_ok(
            unsafe {
                EVP_CIPHER_CTX_ctrl(
                    ctx.as_ptr(),
                    EVP_CTRL_GCM_SET_IVLEN,
                    nonce.len() as c_int,
                    std::ptr::null_mut(),
                )
            },
            "configuring AES-256-GCM nonce length",
        )?;
        openssl_ok(
            unsafe {
                EVP_EncryptInit_ex(
                    ctx.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    key.as_ptr(),
                    nonce.as_ptr(),
                )
            },
            "setting AES-256-GCM key and nonce",
        )?;

        if !aad.is_empty() {
            let mut aad_len = 0;
            openssl_ok(
                unsafe {
                    EVP_EncryptUpdate(
                        ctx.as_ptr(),
                        std::ptr::null_mut(),
                        &mut aad_len,
                        aad.as_ptr(),
                        to_c_int(aad.len(), "AEAD AAD length")?,
                    )
                },
                "processing AES-256-GCM AAD",
            )?;
        }

        let mut ciphertext = vec![0u8; plaintext.len() + AEAD_TAG_LEN];
        let mut ciphertext_len = 0;
        openssl_ok(
            unsafe {
                EVP_EncryptUpdate(
                    ctx.as_ptr(),
                    ciphertext.as_mut_ptr(),
                    &mut ciphertext_len,
                    plaintext.as_ptr(),
                    to_c_int(plaintext.len(), "AEAD plaintext length")?,
                )
            },
            "encrypting AES-256-GCM payload",
        )?;
        let mut final_len = 0;
        openssl_ok(
            unsafe {
                EVP_EncryptFinal_ex(
                    ctx.as_ptr(),
                    ciphertext[ciphertext_len as usize..].as_mut_ptr(),
                    &mut final_len,
                )
            },
            "finalizing AES-256-GCM encryption",
        )?;
        ciphertext.truncate((ciphertext_len + final_len) as usize);

        let mut tag = vec![0u8; AEAD_TAG_LEN];
        openssl_ok(
            unsafe {
                EVP_CIPHER_CTX_ctrl(
                    ctx.as_ptr(),
                    EVP_CTRL_GCM_GET_TAG,
                    AEAD_TAG_LEN as c_int,
                    tag.as_mut_ptr().cast::<c_void>(),
                )
            },
            "reading AES-256-GCM tag",
        )?;
        Ok((ciphertext, tag))
    }

    pub fn decrypt_aes_256_gcm(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>> {
        validate_lengths(key, nonce)?;
        if tag.len() != AEAD_TAG_LEN {
            return Err(QsrlError::DataCorruption(format!(
                "AEAD tag length {} did not match expected {AEAD_TAG_LEN}",
                tag.len()
            )));
        }
        let ctx = CipherCtx::new()?;
        let cipher = unsafe { EVP_aes_256_gcm() };
        if cipher.is_null() {
            return Err(QsrlError::UnsupportedFeature(
                "OpenSSL AES-256-GCM cipher is unavailable".into(),
            ));
        }

        openssl_ok(
            unsafe {
                EVP_DecryptInit_ex(
                    ctx.as_ptr(),
                    cipher,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            "initializing AES-256-GCM decryption",
        )?;
        openssl_ok(
            unsafe {
                EVP_CIPHER_CTX_ctrl(
                    ctx.as_ptr(),
                    EVP_CTRL_GCM_SET_IVLEN,
                    nonce.len() as c_int,
                    std::ptr::null_mut(),
                )
            },
            "configuring AES-256-GCM nonce length",
        )?;
        openssl_ok(
            unsafe {
                EVP_DecryptInit_ex(
                    ctx.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    key.as_ptr(),
                    nonce.as_ptr(),
                )
            },
            "setting AES-256-GCM key and nonce",
        )?;

        if !aad.is_empty() {
            let mut aad_len = 0;
            openssl_ok(
                unsafe {
                    EVP_DecryptUpdate(
                        ctx.as_ptr(),
                        std::ptr::null_mut(),
                        &mut aad_len,
                        aad.as_ptr(),
                        to_c_int(aad.len(), "AEAD AAD length")?,
                    )
                },
                "processing AES-256-GCM AAD",
            )?;
        }

        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut plaintext_len = 0;
        openssl_ok(
            unsafe {
                EVP_DecryptUpdate(
                    ctx.as_ptr(),
                    plaintext.as_mut_ptr(),
                    &mut plaintext_len,
                    ciphertext.as_ptr(),
                    to_c_int(ciphertext.len(), "AEAD ciphertext length")?,
                )
            },
            "decrypting AES-256-GCM payload",
        )?;

        let mut tag_copy = tag.to_vec();
        openssl_ok(
            unsafe {
                EVP_CIPHER_CTX_ctrl(
                    ctx.as_ptr(),
                    EVP_CTRL_GCM_SET_TAG,
                    AEAD_TAG_LEN as c_int,
                    tag_copy.as_mut_ptr().cast::<c_void>(),
                )
            },
            "setting AES-256-GCM tag",
        )?;

        let mut final_len = 0;
        let status = unsafe {
            EVP_DecryptFinal_ex(
                ctx.as_ptr(),
                plaintext[plaintext_len as usize..].as_mut_ptr(),
                &mut final_len,
            )
        };
        if status != 1 {
            return Err(QsrlError::DataCorruption(
                "AES-256-GCM rejected the ciphertext or authentication tag".into(),
            ));
        }
        plaintext.truncate((plaintext_len + final_len) as usize);
        Ok(plaintext)
    }

    struct CipherCtx(NonNull<EvpCipherCtx>);

    impl CipherCtx {
        fn new() -> Result<Self> {
            let ctx = unsafe { EVP_CIPHER_CTX_new() };
            let ctx = NonNull::new(ctx).ok_or_else(|| {
                QsrlError::UnsupportedFeature("OpenSSL could not allocate an AEAD context".into())
            })?;
            Ok(Self(ctx))
        }

        fn as_ptr(&self) -> *mut EvpCipherCtx {
            self.0.as_ptr()
        }
    }

    impl Drop for CipherCtx {
        fn drop(&mut self) {
            unsafe { EVP_CIPHER_CTX_free(self.0.as_ptr()) };
        }
    }

    fn validate_lengths(key: &[u8], nonce: &[u8]) -> Result<()> {
        if key.len() != ARCHIVE_KEY_LEN {
            return Err(QsrlError::UnsupportedFeature(format!(
                "AEAD key length {} did not match expected {ARCHIVE_KEY_LEN}",
                key.len()
            )));
        }
        if nonce.len() != AEAD_NONCE_LEN {
            return Err(QsrlError::UnsupportedFeature(format!(
                "AEAD nonce length {} did not match expected {AEAD_NONCE_LEN}",
                nonce.len()
            )));
        }
        Ok(())
    }

    fn openssl_ok(status: c_int, context: &str) -> Result<()> {
        if status == 1 {
            Ok(())
        } else {
            Err(QsrlError::UnsupportedFeature(context.into()))
        }
    }

    fn to_c_int(value: usize, context: &str) -> Result<c_int> {
        c_int::try_from(value).map_err(|_| {
            QsrlError::UnsupportedFeature(format!("{context} overflowed OpenSSL c_int"))
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "liboqs-backend")]
    use super::KeyImplementation;
    use super::{SignatureAlgorithm, generate_keypair, sign_message, verify_signature};

    #[test]
    fn stub_signature_round_trip() {
        let (private_key, public_key) =
            generate_keypair(SignatureAlgorithm::MlDsa, "test".into()).expect("keygen");
        let message = b"manifest bytes";
        let signature = sign_message(&private_key, message).expect("sign");
        verify_signature(&public_key, message, &signature).expect("verify");
    }

    #[cfg(feature = "liboqs-backend")]
    #[test]
    fn liboqs_signature_round_trip_for_both_algorithms() {
        for algorithm in [SignatureAlgorithm::MlDsa, SignatureAlgorithm::SlhDsa] {
            let (private_key, public_key) =
                generate_keypair(algorithm, format!("test-{}", algorithm.as_str()))
                    .expect("keygen");
            assert_eq!(
                private_key.implementation,
                KeyImplementation::LiboqsSystemV1
            );
            let message = format!("manifest bytes for {}", algorithm.as_str());
            let signature = sign_message(&private_key, message.as_bytes()).expect("sign");
            verify_signature(&public_key, message.as_bytes(), &signature).expect("verify");
        }
    }
}
