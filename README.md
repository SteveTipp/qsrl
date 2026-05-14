# Quantum Sealed Record Layer

Quantum Sealed Record Layer (QSRL) is a Rust prototype for a deterministic,
inspectable archive format focused on authenticity and interoperability first.
The `qsrl` CLI packages files into `.qsrl` archives, builds a canonical
manifest, signs that manifest using a selectable post-quantum algorithm
identifier, and can encrypt archive payloads for one or more ML-KEM recipients.

This repository is for experimentation, not production cryptography. QSRL has
not been audited.

## Prototype goals

- Keep the on-disk format simple and inspectable.
- Keep serialization explicit and deterministic.
- Expose ML-DSA and SLH-DSA as archive-level algorithm choices.
- Keep signatures and ML-KEM + AEAD encryption separated and inspectable.
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
cargo test --locked
```

QSRL currently builds and runs from source. Prebuilt application bundles and
`.dmg` packaging are not provided yet.

Set up and test with real `liboqs` signatures on macOS:

```bash
brew install liboqs
export LIBOQS_DIR="$(brew --prefix liboqs)"
export PKG_CONFIG_PATH="$LIBOQS_DIR/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
cargo test --locked --features liboqs-backend
```

Release validation should use the pinned `Cargo.lock` dependency graph:

```bash
cargo test --locked
cargo test --locked --features liboqs-backend
cargo check --locked --features desktop-ui --bin qsrl-desktop
cargo check --locked --features desktop-ui,liboqs-backend --bin qsrl-desktop
```

Dependency updates should be intentional and reviewed. See
[docs/dependency-policy.md](docs/dependency-policy.md).

Launch the local desktop UI on macOS:

```bash
cargo run --features desktop-ui --bin qsrl-desktop
```

Launch the local desktop UI with real `liboqs` signatures and ML-KEM support:

```bash
cargo run --features desktop-ui,liboqs-backend --bin qsrl-desktop
```

Initialize local defaults:

```bash
cargo run --bin qsrl -- init
```

Generate a keypair:

```bash
cargo run --bin qsrl -- keygen --alg ml-dsa
```

Generate a real `liboqs` keypair:

```bash
cargo run --features liboqs-backend --bin qsrl -- keygen --alg ml-dsa
cargo run --features liboqs-backend --bin qsrl -- keygen --alg slh-dsa
```

Signed-only CLI flow:

Pack a directory:

```bash
cargo run --bin qsrl -- pack examples/sample_input -o examples/sample.qsrl
```

Sign and verify:

```bash
cargo run --bin qsrl -- sign examples/sample.qsrl --key keys/ml-dsa-001.private
cargo run --bin qsrl -- verify examples/sample.qsrl --pubkey keys/ml-dsa-001.public
```

Extract the archive back to a directory:

```bash
cargo run --bin qsrl -- extract examples/sample.qsrl -o examples/unpacked --pubkey keys/ml-dsa-001.public
```

Signed + encrypted CLI flow:

Generate an ML-KEM recipient keypair:

```bash
cargo run --features liboqs-backend --bin qsrl -- recipient-keygen --alg ml-kem
```

Pack an encrypted archive for one or more recipients:

```bash
cargo run --features liboqs-backend --bin qsrl -- pack examples/sample_input -o examples/sample-encrypted.qsrl --recipient keys/ml-kem-001.public
```

Sign and verify the encrypted archive manifest:

```bash
cargo run --features liboqs-backend --bin qsrl -- sign examples/sample-encrypted.qsrl --key keys/ml-dsa-001.private
cargo run --features liboqs-backend --bin qsrl -- verify examples/sample-encrypted.qsrl --pubkey keys/ml-dsa-001.public
```

Decrypt and extract the encrypted archive:

```bash
cargo run --features liboqs-backend --bin qsrl -- extract examples/sample-encrypted.qsrl -o examples/unpacked-encrypted --pubkey keys/ml-dsa-001.public --recipient-key keys/ml-kem-001.private
```

For detached signatures, pass the sibling signature file explicitly:

```bash
cargo run --bin qsrl -- extract examples/sample-detached.qsrl -o examples/unpacked-detached --pubkey keys/ml-dsa-001.public --sig examples/sample-detached.qsrl.sig
```

Sign and verify with the real backend:

```bash
cargo run --features liboqs-backend --bin qsrl -- sign examples/sample.qsrl --key keys/ml-dsa-001.private
cargo run --features liboqs-backend --bin qsrl -- verify examples/sample.qsrl --pubkey keys/ml-dsa-001.public
```

Inspect the archive:

```bash
cargo run --bin qsrl -- inspect examples/sample.qsrl
```

Run the comparison harness:

```bash
cargo run --bin qsrl -- compare examples/sample_input -o comparison-output --key keys/ml-dsa-001.private
```

## Architecture

QSRL keeps signatures separate from encryption on purpose. Authenticity binds
the canonical manifest and optional block table, which lets the archive format
stabilize around deterministic packaging first. Confidentiality layers on top by
encrypting only the archive payload blob, while recipient records carry
ML-KEM-wrapped access to a random archive key. That keeps the signed identity
model stable: signatures continue to bind canonical packaging choices and file
identity, while encryption controls who can recover the payload contents.

## Crypto backend status

Real `liboqs` support is now wired in through a minimal direct Rust-to-C FFI
layer that preserves the current archive semantics, manifest format,
signature-record structure, and CLI shape.

Build modes:

- Stub-only mode: `cargo test --locked`
- Real `liboqs` mode: `cargo test --locked --features liboqs-backend`

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

## Local UI

QSRL now includes a small local desktop app, `qsrl-desktop`, built with
`egui/eframe`. It is a thin front end over the existing Rust archive, signing,
verification, extraction, and inspection logic, and it keeps all file and key
operations local on disk.

What it can do:

- pack archives with manifest and compression choices
- sign archives with embedded or detached signatures
- verify archives and show signature/hash status
- extract signed or encrypted archives with optional keys
- inspect archive metadata and file entries in a readable panel

Notes:

- The desktop UI is local-only and intended for private/demo use right now.
- It does not add any network features, telemetry, accounts, or sync.
- The existing `qsrl` CLI remains fully functional.

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
