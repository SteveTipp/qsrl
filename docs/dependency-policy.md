# Dependency Policy

Quantum Sealed Record Layer (QSRL) is an experimental cryptography/archive
prototype, so dependency changes should be explicit, reviewable, and
reproducible.

## Locked Dependencies

`Cargo.lock` is intentionally committed. It pins the exact dependency versions
resolved by Cargo so release validation and local reproduction use the same
dependency graph unless a dependency update is made intentionally.

Normal release validation should use Cargo's `--locked` flag:

```bash
cargo test --locked
cargo test --locked --features liboqs-backend
cargo check --locked --features desktop-ui --bin qsrl-desktop
cargo check --locked --features desktop-ui,liboqs-backend --bin qsrl-desktop
```

If `--locked` fails because `Cargo.lock` needs to change, treat that as a
dependency update rather than a routine validation failure.

## Updating Dependencies

Dependency updates should be intentional and reviewed. Prefer targeted updates
when possible:

```bash
cargo update -p <crate>
```

After any dependency update, review the `Cargo.lock` diff and rerun the locked
validation commands before release.

## Vendoring

`cargo vendor` can be used later if QSRL needs offline or vendored dependency
snapshots. This repository does not currently vendor dependencies.
