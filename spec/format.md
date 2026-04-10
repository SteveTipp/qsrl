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
4. File payload area
5. Optional embedded signature record

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
- Bytes `46..54`: reserved recipient-record length for future encryption extensions
- Bytes `54..64`: reserved zero padding

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

## Signature record

The same signature-record encoding is used both for embedded signatures and for
detached `.qsrl.sig` files. The record contains:

- Signature algorithm
- Signature scope
- Backend implementation code
- Public-key fingerprint
- Digest of the canonical signed payload
- Signature bytes

## Future encryption extension points

QSRL does not implement encryption in this prototype. The header reserves space
for future recipient records so later work can add ML-KEM-based file-key
wrapping plus AEAD payload encryption without redefining the archive identity
model or signature scope.
