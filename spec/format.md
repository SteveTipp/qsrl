# Quantum Sealed Record Layer Format

This document describes the prototype QSRL container layout.

## Goals

- Simple fixed header
- Canonical manifest serialization
- Explicit block table
- Deterministic file ordering
- Archive-level signature algorithm selection
- Reserved space for future encryption metadata

## High-level layout

1. Fixed 64-byte archive header
2. Canonical manifest block
3. Canonical block table
4. Optional encryption section with recipient records
5. File payload area
6. Optional embedded signature record

Detached signatures use the same signature-record encoding in a sibling file.

## Header fields

- Bytes `0..4`: magic `QSRL`
- Bytes `4..6`: header version `1`
- Bytes `6..8`: format version `1`
- Byte `8`: manifest encoding
- Byte `9`: signature placement
- Byte `10`: signature scope
- Byte `11`: compression mode
- Byte `12`: compression layout
- Byte `13`: flags
- Bytes `14..22`: manifest length
- Bytes `22..30`: block table length
- Bytes `30..38`: payload length
- Bytes `38..46`: embedded signature length
- Bytes `46..54`: encryption section length
- Bytes `54..64`: reserved zero padding

Current header flag bits used by the prototype:

- `0x01`: embedded signature present
- `0x02`: encrypted payload present

## Manifest contents

- Format version
- File paths
- File sizes
- SHA-256 digests
- Compression mode
- Selected signature algorithm
- Deterministic normalization notes

Two canonical encodings are implemented:

- `text-v1`: inspectable line-oriented canonical text
- `binary-v1`: compact canonical binary structure

Both require sorted entries, normalized forward-slash paths, and omitted file
timestamps.

## Block table contents

- Stored offset
- Stored length
- Raw offset
- Raw length
- Compression mode

The block table is separate so the prototype can compare signing the manifest
alone versus signing the manifest plus transport-level layout metadata.

## Encryption section

When present, the encryption section sits between the block table and the
payload. It contains:

- KEM family identifier
- Fixed KEM method name for the archive
- AEAD algorithm identifier
- Payload nonce
- Payload authentication tag
- One or more recipient records

Recipient records contain:

- Backend implementation code
- Recipient public-key fingerprint
- ML-KEM ciphertext for that recipient
- Recipient wrap nonce
- Wrapped archive key ciphertext
- Recipient wrap authentication tag

Current prototype choices:

- KEM family: `ml-kem`
- Fixed KEM method: `ML-KEM-768`
- Payload AEAD: `AES-256-GCM`
- Archive key size: 32 bytes
- Payload nonce size: 12 bytes
- Payload tag size: 16 bytes

The payload section stores only ciphertext when encryption is enabled. The
manifest and block table remain plaintext so canonical archive identity and
signatures stay stable.

## Signature record

The same signature-record encoding is used both for embedded signatures and for
detached `.qsrl.sig` files. The record contains:

- Signature algorithm
- Signature scope
- Backend implementation code
- Public-key fingerprint
- Digest of the canonical signed payload
- Signature bytes

Current backend codes used by the prototype:

- `1`: `stub-lamport-v1`
- `2`: `liboqs-system-v1`

## Signing and encryption split

QSRL signatures continue to bind the canonical manifest and, optionally, the
block table. They do not sign ciphertext bytes directly. Encryption protects the
payload section and archive-key access, while signatures continue to define
archive identity and transport-level determinism.
