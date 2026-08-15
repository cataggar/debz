# Documentation

- [Project status and API overview](project-status.md) describes implemented modules, public boundaries, limitations, and transaction-plan schema.
- [Authenticated repository refresh](authenticated-refresh.md) explains trusted refresh usage, policy, provenance, and cache behavior.
- [Verified package acquisition](package-acquisition.md) documents authenticated solver selection, download policy, SHA-256 CAS publication, offline use, and bounded garbage collection.
- [Immutable multi-repository policy](multi-repository-policy.md) documents deterministic source normalization, authenticated orchestration, atomic publication, stale/cache-only policy, and solver precedence.
- [OpenPGP verification boundary](openpgp-verifier.md) documents the exact supported profile, security limitations, implementation decision, and verification outcomes.
- [Solver and planning semantics](solver-planning.md) documents Debian policy, determinism, and ordered plans.
- [Transaction plan schema v2](../schema/transaction-plan-v2.json) is the current canonical schema; [v1](../schema/transaction-plan-v1.json) remains available for compatibility.
- [Debian payload validation](deb-payload-validation.md) documents resource limits, tar/path/link policy, identity checks, inventories, diagnostics, and fuzzing.
