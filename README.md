# Quantum Sealed Record Layer

Quantum Sealed Record Layer (QSRL) is a Rust prototype for a deterministic,
inspectable archive format focused on authenticity and interoperability first.
The `qsrl` CLI packages files into `.qsrl` archives, builds a canonical
manifest, signs that manifest using a selectable post-quantum algorithm
identifier, and can encrypt archive payloads for one or more ML-KEM recipients.

This repository is for experimentation, not production cryptography.

## Prototype goals

- Keep the on-disk format simple and inspectable.
- Keep serialization explicit and deterministic.
- Expose ML-DSA and SLH-DSA as archive-level algorithm choices.
- Preserve clear extension points for future ML-KEM + AEAD encryption work.
- Make protocol choices easy to compare.

## Status

The first working prototype is implemented in Rust and keeps the archive,
manifest, signing, and payload-encryption seams easy to inspect. A real
`liboqs` backend is now wired into the existing `src/crypto.rs` replacement
boundary behind the `liboqs-backend` Cargo feature, while the dependency-free
stub path remains available for offline experimentation with signed-only
archives.

## Quick start

Build:

```bash
cargo build
cargo test
```

Build and test with real `liboqs` signatures on macOS:

```bash
brew install liboqs
export LIBOQS_DIR="$(brew --prefix liboqs)"
export PKG_CONFIG_PATH="$LIBOQS_DIR/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
cargo test --features liboqs-backend
```

Initialize local defaults:

```bash
cargo run -- init
```

Generate a keypair:

```bash
cargo run -- keygen --alg ml-dsa
```

Generate a real `liboqs` keypair:

```bash
cargo run --features liboqs-backend -- keygen --alg ml-dsa
cargo run --features liboqs-backend -- keygen --alg slh-dsa
```

Generate an ML-KEM recipient keypair:

```bash
cargo run --features liboqs-backend -- recipient-keygen --alg ml-kem
```

Pack a directory:

```bash
cargo run -- pack examples/sample_input -o examples/sample.qsrl
```

Pack an encrypted archive for one or more recipients:

```bash
cargo run --features liboqs-backend -- pack examples/sample_input -o examples/sample-encrypted.qsrl --recipient keys/ml-kem-001.public
```

Sign and verify:

```bash
cargo run -- sign examples/sample.qsrl --key keys/ml-dsa-001.private
cargo run -- verify examples/sample.qsrl --pubkey keys/ml-dsa-001.public
```

Extract the archive back to a directory:

```bash
cargo run -- extract examples/sample.qsrl -o examples/unpacked --pubkey keys/ml-dsa-001.public
```

Decrypt and extract an encrypted archive:

```bash
cargo run --features liboqs-backend -- extract examples/sample-encrypted.qsrl -o examples/unpacked-encrypted --pubkey keys/ml-dsa-001.public --recipient-key keys/ml-kem-001.private
```

For detached signatures, pass the sibling signature file explicitly:

```bash
cargo run -- extract examples/sample-detached.qsrl -o examples/unpacked-detached --pubkey keys/ml-dsa-001.public --sig examples/sample-detached.qsrl.sig
```

Sign and verify with the real backend:

```bash
cargo run --features liboqs-backend -- sign examples/sample.qsrl --key keys/ml-dsa-001.private
cargo run --features liboqs-backend -- verify examples/sample.qsrl --pubkey keys/ml-dsa-001.public
```

Inspect the archive:

```bash
cargo run -- inspect examples/sample.qsrl
```

Run the comparison harness:

```bash
cargo run -- compare examples/sample_input -o comparison-output --key keys/ml-dsa-001.private
```

## Architecture

QSRL keeps signatures separate from future encryption on purpose. Authenticity
binds the canonical manifest and optional block table, which lets the archive
format stabilize around deterministic packaging first. Confidentiality layers on
top by encrypting only the archive payload blob, while recipient records carry
ML-KEM-wrapped access to a random archive key. That keeps the signed identity
model stable: signatures continue to bind canonical packaging choices and file
identity, while encryption controls who can recover the payload contents.

## Crypto backend status

Real `liboqs` support is now wired in through a minimal direct Rust-to-C FFI
layer that preserves the current archive semantics, manifest format,
signature-record structure, and CLI shape.

Build modes:

- Stub-only mode: `cargo test`
- Real `liboqs` mode: `cargo test --features liboqs-backend`

Current family-to-parameter mapping in `liboqs` mode:

- `ml-dsa` -> `ML-DSA-65`
- `slh-dsa` -> `SLH_DSA_PURE_SHA2_192S`
- `ml-kem` -> `ML-KEM-768`
- payload AEAD -> `AES-256-GCM`

The archive manifest and CLI continue to expose the family-level choices
`ml-dsa`, `slh-dsa`, and `ml-kem`; the concrete parameter set is stored in local
key metadata and handled inside the crypto backend.

See [docs/crypto-backend.md](docs/crypto-backend.md)
for setup steps, feature usage, and backend notes.

## Commands

- `qsrl init`
- `qsrl pack <input_path> -o <archive.qsrl> [--recipient <recipient_public_key>]...`
- `qsrl keygen --alg ml-dsa`
- `qsrl keygen --alg slh-dsa`
- `qsrl recipient-keygen --alg ml-kem`
- `qsrl sign <archive.qsrl> --key <private_key>`
- `qsrl verify <archive.qsrl> --pubkey <public_key>`
- `qsrl extract <archive.qsrl> -o <output_dir> [--recipient-key <private_key>]`
- `qsrl inspect <archive.qsrl>`
- `qsrl compare <input_path> -o <output_dir> --key <private_key>`

## Repository layout

- `docs/` notes on protocol experiments and tradeoffs
- `examples/` runnable example inputs and commands
- `spec/` archive format notes
- `src/` Rust library and CLI
- `tests/` integration tests
