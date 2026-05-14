# Changelog

All notable local prototype milestones for Quantum Sealed Record Layer (QSRL)
are summarized here. QSRL is experimental software and has not been audited for
production security use.

## v0.2.9

- Resolved Clippy warnings before the initial developer-preview release.
- Confirmed lint-clean validation with strict warnings enabled.

## v0.2.8

- Hardened archive parsing, randomness, extraction, and key handling before
  release.
- Removed insecure RNG fallback behavior.
- Added stricter malformed archive/count validation.
- Added RLE expansion bounds.
- Hardened extraction against symlink paths and overwrites.
- Rejected trailing archive bytes.
- Strengthened encrypted-archive verify wording.

## v0.2.7

- Added dependency policy documentation.
- Updated release validation guidance to use Cargo's `--locked` flag.

## v0.2.6

- Prepared repository documentation and release hygiene for an initial
  open-source developer-preview release.
- Added release checklist and security policy.

## v0.2.5

- Added a custom desktop app icon for the local QSRL desktop app.

## v0.2.4

- Added a Qwork-inspired desktop UI theme with black backgrounds, white text,
  and green highlights.

## v0.2.3

- Added in-app key generation for ML-DSA, SLH-DSA, and ML-KEM keys.
- Refined desktop UI usability for local demo workflows.

## v0.2.2

- Polished the local desktop UI for clearer status handling and local demo use.

## v0.2.1

- Added a local `egui/eframe` desktop UI over the existing QSRL Rust logic.

## v0.2.0

- Added ML-KEM recipient encryption with AES-GCM payload protection.
- Preserved the separation between manifest signatures and payload
  confidentiality.

## v0.1.1

- Added verified archive extraction.
- Added extraction coverage for supported compression layouts.

## v0.1.0

- Added real `liboqs`-backed ML-DSA and SLH-DSA signature support.
- Preserved the documented prototype-only stub backend for dependency-free
  experimentation.
