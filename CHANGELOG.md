# Changelog

## 0.1.0-alpha.2

Hardening candidate; release publication is separate from this version change.

- Preserve foreground service ownership after supervisor loss; refuse reset/restart while cleanup is unproven.
- Recheck frozen baseline contents and executable modes before constructing repairs.
- Build repairs transactionally, retain failure evidence, and generate applicable Git patches including missing final newlines and explicit executable entrypoints.
- Accept computed credential-loading expressions while screening literal credentials; redact common structured JSON credential fields in retrieved evidence.
- Clarify same-workspace setup idempotency, user-data preservation, actionable runbook commands and contract-operation coverage from external field feedback.
- Add targeted recovery/CLI regressions and repeatable statement/branch coverage including supervisor subprocesses, with development-only tooling and CI reports.

## 0.1.0-alpha.1

Initial public alpha, prepared from the private prototype.

- Source-cited stack discovery and runner selection that preserves existing native/Compose conventions.
- Explicit native disposable execution and owned native foreground development lifecycle; optional constrained Docker execution.
- Reviewable repair snapshots, bounded acceptance runs, protected checks and drift detection.
- Reconciled project stack/runbook guidance with policy preservation and explicit evidence/fidelity limits.

Alpha limits: bounded static recognition, POSIX native runtime, no generic Compose orchestration backend, no enforced harness filesystem isolation, no universal framework or production-provider equivalence. See README and skill references for current verification scope.
