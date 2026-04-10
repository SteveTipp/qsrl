# QSRL Crypto Backend Status

## Current state

QSRL now has two backend modes behind the existing `src/crypto.rs` seam:

- Default build: `stub-lamport-v1`
- `cargo ... --features liboqs-backend`: real `liboqs` signatures, ML-KEM recipient wrapping, and AES-256-GCM payload encryption

The default stub backend remains intentionally:

- Offline and dependency-free
- Hash-based and easy to inspect
- Good enough to exercise keygen, sign, verify, archive mutation, and test
  workflows
- Not a substitute for production ML-DSA or SLH-DSA

The `liboqs` feature-backed mode uses a thin direct FFI layer to the system
`liboqs` C API and preserves the current CLI surface:

- `qsrl keygen --alg ml-dsa`
- `qsrl keygen --alg slh-dsa`
- `qsrl recipient-keygen --alg ml-kem`
- `qsrl sign`
- `qsrl verify`
- `qsrl pack ... --recipient ...`
- `qsrl extract ... --recipient-key ...`

## liboqs mapping

The CLI and archive manifest stay at the family level, but the real backend
maps those families to fixed parameter sets today:

- `ml-dsa` -> `ML-DSA-65`
- `slh-dsa` -> `SLH_DSA_PURE_SHA2_192S`
- `ml-kem` -> `ML-KEM-768`
- payload AEAD -> `AES-256-GCM`

That keeps the user experience stable without expanding the archive semantics.
The concrete method name is stored in local key files as `method_name`.

## macOS setup

Homebrew install:

```bash
brew install liboqs
export LIBOQS_DIR="$(brew --prefix liboqs)"
export PKG_CONFIG_PATH="$LIBOQS_DIR/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
```

Build and test the real backend:

```bash
cargo test --features liboqs-backend
```

Run the real backend from the CLI:

```bash
cargo run --features liboqs-backend -- keygen --alg ml-dsa
cargo run --features liboqs-backend -- keygen --alg slh-dsa
cargo run --features liboqs-backend -- recipient-keygen --alg ml-kem
cargo run --features liboqs-backend -- pack examples/sample_input -o examples/sample.qsrl --alg slh-dsa --recipient keys/ml-kem-001.public
cargo run --features liboqs-backend -- sign examples/sample.qsrl --key keys/slh-dsa-001.private
cargo run --features liboqs-backend -- verify examples/sample.qsrl --pubkey keys/slh-dsa-001.public
cargo run --features liboqs-backend -- extract examples/sample.qsrl -o examples/unpacked --pubkey keys/slh-dsa-001.public --recipient-key keys/ml-kem-001.private
```

Notes:

- `LIBOQS_DIR` is the main override if `pkg-config` does not find your install.
- `PKG_CONFIG_PATH` is usually enough for Homebrew and other custom prefixes.
- If you use a non-standard shared-library location, you may also need your
  platform’s runtime loader path set, such as `DYLD_LIBRARY_PATH`.

## Build modes

Stub-only mode:

```bash
cargo test
```

Real `liboqs` mode:

```bash
cargo test --features liboqs-backend
```

## What is now wired in

1. Real ML-DSA key generation, signing, and verification via `liboqs`.
2. Real SLH-DSA key generation, signing, and verification via `liboqs`.
3. Real ML-KEM-768 recipient key generation plus archive-key wrapping via `liboqs`.
4. AES-256-GCM payload encryption and decryption for encrypted QSRL archives.
5. Backend-aware key read/write helpers that preserve the current QSRL archive
   and signature-record semantics.
6. Automated tests covering signed-only and signed+encrypted round trips in `liboqs` mode.
7. Continued support for the legacy stub backend for offline experimentation with
   signed-only archives.

## Desired swap boundary

The active replacement boundary remains `src/crypto.rs`:

- `generate_keypair`
- `sign_message`
- `verify_signature`
- `generate_recipient_keypair`
- `wrap_archive_key_for_recipient`
- `unwrap_archive_key_for_recipient`
- `encrypt_aead`
- `decrypt_aead`
- key read/write helpers

Everything else in the repository should continue to work with minimal change
once that seam is replaced.
