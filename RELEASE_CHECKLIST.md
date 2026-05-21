# Release Checklist

This checklist was used to validate Quantum Sealed Record Layer (QSRL) before its initial public developer-preview release.

Use it again before future public releases or major updates.

- Run `cargo test --locked`.
- Run `cargo test --locked --features liboqs-backend`.
- Run `cargo check --locked --features desktop-ui --bin qsrl-desktop`.
- Run `cargo check --locked --features desktop-ui,liboqs-backend --bin qsrl-desktop`.
- Launch the desktop UI locally and smoke-test pack, sign, verify, extract, and
  inspect.
- Verify no generated keys, private keys, private archives, detached
  signatures, or extracted payloads are tracked.
- Verify `.gitignore` protects generated artifacts such as `keys/`, `*.private`,
  `*.public`, `*.qsrl`, `*.qsrl.sig`, `comparison-output/`, and `unpacked*/`.
- Verify `README.md` clearly says QSRL is experimental and not audited.
- Verify `LICENSE` is present.
- Verify screenshots, if later added, do not leak private paths, names, keys, or
  archive contents.
- Verify no `.dmg` or other release package has been added unless a packaging
  pass was intentionally performed.
