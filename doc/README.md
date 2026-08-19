# Documentation

- [Stable product API and CLI contract](product-api.md)
- [Release installation and runtime requirements](release-installation.md) describes version injection, the installed tree, and Linux dynamic dependencies.

- [Project status and API overview](project-status.md) describes implemented modules, public boundaries, limitations, and transaction-plan schema.
- [Authenticated repository refresh](authenticated-refresh.md) explains trusted refresh usage, policy, provenance, and cache behavior.
- [Verified package acquisition](package-acquisition.md) documents authenticated solver selection, download policy, SHA-256 CAS publication, offline use, and bounded garbage collection.
- [Immutable multi-repository policy](multi-repository-policy.md) documents deterministic source normalization, authenticated orchestration, atomic publication, stale/cache-only policy, and solver precedence.
- [OpenPGP verification boundary](openpgp-verifier.md) documents the exact supported profile, security limitations, implementation decision, and verification outcomes.
- [Solver and planning semantics](solver-planning.md) documents Debian policy, determinism, and ordered plans.
- [Transaction plan schema v2](../schema/transaction-plan-v2.json) is the current canonical schema; [v1](../schema/transaction-plan-v1.json) remains available for compatibility.
- [Debian payload validation](deb-payload-validation.md) documents resource limits, tar/path/link policy, identity checks, inventories, diagnostics, and fuzzing.
- [Dpkg transaction executor](transaction-executor.md) documents install-root safety, locks, argv/environment policy, ordering, triggers, force policy, and failure provenance.
- [Exact closure locks and transaction provenance](exact-locks-and-provenance.md) documents canonical schemas, reproduction constraints, redaction, persistence, recovery evidence, and final verification.
- [Transaction recovery](transaction-recovery.md) documents durable journals, explicit repair, and exact post-state verification.
- [Hermetic integration roots](integration-roots.md) documents deterministic signed fixtures, disposable native/foreign roots, CI lanes, and local prerequisites.
- [zvmi Debian-family backend](zvmi-package-family.md) defines the versioned Ubuntu/Debian image-builder boundary, explicit inputs, locks, provenance, cache policy, and failure contract.
- [Threat model and safety limits](threat-model.md) defines untrusted surfaces, security properties, and residual risks.
- [Safety CI, fuzzing and audits](safety-ci.md) documents fuzz targets, bounded CI/local campaigns, safety modes, and static policy gates.
