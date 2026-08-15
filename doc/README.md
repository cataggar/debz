# Documentation

- [Project status and API overview](project-status.md) describes implemented modules, public boundaries, limitations, and transaction-plan schema.
- [Authenticated repository refresh](authenticated-refresh.md) explains trusted refresh usage, policy, provenance, and cache behavior.
- [Verified package acquisition](package-acquisition.md) documents authenticated solver selection, download policy, SHA-256 CAS publication, offline use, and bounded garbage collection.
- [OpenPGP verification boundary](openpgp-verifier.md) documents the exact supported profile, security limitations, implementation decision, and verification outcomes.
- [Transaction plan schema](../schema/transaction-plan-v1.json) is the canonical JSON Schema for version 1 plans.
- [Debian payload validation](deb-payload-validation.md) documents resource limits, tar/path/link policy, identity checks, inventories, diagnostics, and fuzzing.
