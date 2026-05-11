# Security Policy

Quantum Sealed Record Layer (QSRL) is an experimental archive and cryptography
prototype. It has not been independently audited, and it should not be used for
production secrets yet.

## Reporting Vulnerabilities

Please report suspected vulnerabilities responsibly and avoid publishing exploit
details publicly before maintainers have had time to review and respond.

Contact: TODO before publication: add a dedicated security contact or reporting
channel.

## Scope

Reports related to archive parsing, path handling, signing, verification,
recipient encryption, key handling, or desktop UI file handling are welcome.

Generated keys, private archives, detached signatures, extracted payloads, and
local comparison outputs should not be committed to the repository.

## Prototype Notice

QSRL currently exists for experimentation with deterministic archive formats,
post-quantum signatures, and recipient encryption. Security-sensitive design
choices may change as the prototype evolves.
