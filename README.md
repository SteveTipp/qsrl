# Quantum Sealed Record Layer

Quantum Sealed Record Layer (QSRL) is a Rust prototype for a deterministic,
inspectable archive format focused on authenticity and interoperability first.
The `qsrl` CLI packages files into `.qsrl` archives, builds a canonical
manifest, and signs that manifest using a selectable post-quantum algorithm
identifier.

This repository is for experimentation, not production cryptography.

## Prototype goals

- Keep the on-disk format simple and inspectable.
- Keep serialization explicit and deterministic.
- Expose ML-DSA and SLH-DSA as archive-level algorithm choices.
- Preserve clear extension points for future ML-KEM + AEAD encryption work.
- Make protocol choices easy to compare.

## Status

The first working prototype is implemented in Rust and intentionally keeps the
archive, manifest, and signing seams easy to inspect. Where real PQ signature
integration is not yet wired in, the code documents the gap clearly and keeps a
clean replacement boundary.

## Quick start

Build:

```bash
cargo build
cargo test
```

Initialize local defaults:

```bash
cargo run -- init
```

Generate a prototype keypair:

```bash
cargo run -- keygen --alg ml-dsa
```

Pack a directory:

```bash
cargo run -- pack examples/sample_input -o examples/sample.qsrl
```

Sign and verify:

```bash
cargo run -- sign examples/sample.qsrl --key keys/ml-dsa-001.private
cargo run -- verify examples/sample.qsrl --pubkey keys/ml-dsa-001.public
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
format stabilize around deterministic packaging first. Future confidentiality
can then layer on recipient records, file-key wrapping with ML-KEM, and AEAD
payload protection without changing what is signed or how file identity is
described in the manifest.

## Crypto backend status

This repository exposes ML-DSA and SLH-DSA as the archive-level choices, but
the current offline build uses a documented prototype-only hash-based backend
called `stub-lamport-v1` under that interface. This keeps the archive format,
key metadata, sign/verify flow, and protocol experiments runnable without
claiming production security.

Exact wiring still to do for real ML-DSA and SLH-DSA support:

- Add a real backend module backed by `liboqs` or a small Rust-to-C FFI shim.
- Map `ml-dsa` and `slh-dsa` to concrete backend algorithm identifiers.
- Replace stub key generation with real backend keypair generation.
- Replace stub sign/verify calls while preserving the current archive and
  signature-record interfaces.
- Add backend-specific test vectors and compatibility checks.

See `docs/crypto-backend.md` for the current seam and swap plan.

## Commands

- `qsrl init`
- `qsrl pack <input_path> -o <archive.qsrl>`
- `qsrl keygen --alg ml-dsa`
- `qsrl keygen --alg slh-dsa`
- `qsrl sign <archive.qsrl> --key <private_key>`
- `qsrl verify <archive.qsrl> --pubkey <public_key>`
- `qsrl inspect <archive.qsrl>`
- `qsrl compare <input_path> -o <output_dir> --key <private_key>`

## Repository layout

- `docs/` notes on protocol experiments and tradeoffs
- `examples/` runnable example inputs and commands
- `spec/` archive format notes
- `src/` Rust library and CLI
- `tests/` integration tests
