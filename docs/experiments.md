# QSRL Protocol Experiments

QSRL is intentionally built to compare protocol choices without committing to a
production design too early.

The repository includes a built-in comparison harness:

```bash
cargo run -- compare examples/sample_input -o comparison-output --key keys/ml-dsa-001.private
```

That command materializes archive variants for the experiment matrix and writes
`comparison-output/comparison.txt`.

## Experiment 1: Signature placement

Options:

- Detached signature file
- Embedded signature block

Implemented in the CLI:

- `qsrl sign ... --placement detached`
- `qsrl sign ... --placement embedded`

Questions:

- What is easier to transport across operating systems?
- What is easier to inspect with simple tooling?
- How much archive rewriting is required when signatures are embedded?

## Experiment 2: Canonical manifest serialization

Options:

- Canonical text form
- Canonical binary form

Implemented in the CLI:

- `qsrl pack ... --manifest-encoding text-v1`
- `qsrl pack ... --manifest-encoding binary-v1`

Questions:

- How much inspectability do we gain with text?
- How much size reduction and parser simplicity do we gain with binary?
- Which form is easiest to keep deterministic across platforms?

## Experiment 3: Compression layout

Options:

- No compression
- Whole-archive compression
- Per-file compression

Implemented in the CLI:

- `qsrl pack ... --compression none --compression-layout per-file`
- `qsrl pack ... --compression rle --compression-layout per-file`
- `qsrl pack ... --compression rle --compression-layout whole-archive`

Questions:

- Which layout makes verification simplest?
- Which layout preserves streaming and random-access options later?
- Which layout gives the best size tradeoff for mixed file trees?

## Other protocol knobs

- Manifest scope: manifest only vs manifest plus block table
- Optional experimental per-file signatures
- Normalized paths and timestamp stripping
- Exactly one signature scheme per archive in v1
- Reserved header space for future recipient records

Current prototype note:

- `manifest` and `manifest+block-table` signature scopes are implemented.
- `per-file` signatures remain a reserved experimental placeholder.
- The current compression codec is intentionally simple RLE so layout choices can
  be compared without introducing external dependencies.
