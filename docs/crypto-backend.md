# QSRL Crypto Backend Status

## Current state

The current Rust prototype keeps the archive and CLI names aligned with the
current NIST terms ML-DSA and SLH-DSA, but the actual local backend is
`stub-lamport-v1`.

That backend is intentionally:

- Offline and dependency-free
- Hash-based and easy to inspect
- Good enough to exercise keygen, sign, verify, archive mutation, and test
  workflows
- Not a substitute for production ML-DSA or SLH-DSA

## Why this seam exists

`liboqs` is not available in this local environment, and the prototype is meant
to stay runnable without external downloads. The stub backend keeps the command
surface and archive metadata stable while real algorithm wiring remains
isolated.

## What remains to wire up

1. Add a real backend module backed by `liboqs` or a thin Rust-to-C FFI layer.
2. Replace stub key generation with backend-generated ML-DSA and SLH-DSA keys.
3. Replace stub sign and verify calls with backend operations.
4. Preserve the existing archive manifest, signature-record, and key metadata
   shapes where practical so protocol experiments do not need to change.
5. Add backend-specific tests using fixed vectors and cross-tool verification.

## Desired swap boundary

The intended replacement boundary is the current `src/crypto.rs` module:

- `generate_keypair`
- `sign_message`
- `verify_signature`
- key read/write helpers

Everything else in the repository should continue to work with minimal change
once that seam is replaced.
