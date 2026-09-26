# Release, audit, and snapshot test inventory

The former Python test entry points are owned by `test/release-tooling.zig`,
`test/security-policy.zig`, and `test/real-snapshot-policy.zig`. The table maps
each previous case to the Zig test that preserves its assertions. Several cases
share one Zig test with independent mutations.

## Release (`tools/test_release.py`)

| Previous case | Zig test (`test/release-tooling.zig`, `release:` prefix) |
| --- | --- |
| `test_strict_tags_and_consistency` | strict tags, version consistency, and exact four asset names |
| `test_binary_archives_are_deterministic` | deterministic gzip and xz archives retain canonical modes, installed policies, and runtime |
| `test_missing_licenses_are_rejected` | missing and divergent installed licenses, cutover policies, and runtime are rejected |
| `test_missing_or_divergent_cutover_policies_are_rejected` | missing and divergent installed licenses, cutover policies, and runtime are rejected |
| `test_static_x64_and_arm64_elfs_are_accepted` | complete x64/arm64 verification rejects forbidden sidecars and nonregular assets |
| `test_pt_interp_is_rejected` | ELF architecture, dynamic loader, needed libraries, and malformed headers refuse packaging |
| `test_dt_needed_without_section_headers_is_rejected` | ELF architecture, dynamic loader, needed libraries, and malformed headers refuse packaging |
| `test_pt_dynamic_offset_virtual_mapping_bypass_is_rejected` | ELF architecture, dynamic loader, needed libraries, and malformed headers refuse packaging |
| `test_malformed_elf_is_rejected` | ELF architecture, dynamic loader, needed libraries, and malformed headers refuse packaging |
| `test_previous_dynamic_runtime_manifest_is_rejected` | missing and divergent installed licenses, cutover policies, and runtime are rejected |
| `test_unsafe_duplicate_link_and_modes_are_rejected` | traversal, duplicate, link, special-file, mode, order, and install-path archive mutations fail with diagnostics |
| `test_unexpected_binary_install_path_is_rejected` | complete archive with unexpected installation path is rejected after required-file checks |
| `test_nondeterministic_metadata_and_order_are_rejected` | traversal, duplicate, link, special-file, mode, order, and install-path archive mutations fail with diagnostics |
| `test_archive_audit_accepts_portable_compression_variants` | portable compression levels are accepted but noncanonical tar payloads are refused |
| `test_archive_container_corruption_trailing_and_payload_mismatch_are_rejected` | archive container corruption, trailing bytes, and noncanonical gzip metadata are rejected; portable compression levels are accepted but noncanonical tar payloads are refused |
| `test_archived_binary_linkage_is_revalidated` | archived binary architecture, dynamic dependencies and runtime are revalidated |
| `test_complete_release_verification` | complete x64/arm64 verification rejects forbidden sidecars and nonregular assets |
| `test_release_install_ships_every_document` | every document and schema is named by release-install manifest and installed schemas match source; `tools/test-release-install.sh` byte-compares both installed copies of every schema |

## Security (`tools/test_security_audit.py`)

| Previous case | Zig test (`test/security-policy.zig`, `security:` prefix) |
| --- | --- |
| `test_digest_cutover_rejects_new_raw_package_authority` | new raw package authority, schema digest field and fixed cache layout are rejected |
| `test_digest_cutover_rejects_new_sha256_only_schema_field` | new raw package authority, schema digest field and fixed cache layout are rejected |
| `test_digest_cutover_rejects_fixed_sha256_cas_path` | new raw package authority, schema digest field and fixed cache layout are rejected |
| `test_digest_cutover_rejects_unreviewed_raw_control_field` | new raw package authority, schema digest field and fixed cache layout are rejected |
| `test_digest_cutover_rejects_inventory_drift` | frozen digest inventory, typed authority, and narrow reviewed compatibility |
| `test_fresh_helper_bootstrap_inventory_rejects_mutation`, `test_signed_consumer_evidence_inventory_rejects_mutation`, `test_projected_repository_evidence_inventory_refuses_mutation` | recovery bootstrap, signed consumer, and repository evidence are inventoried |
| `test_signed_consumer_per_receipt_checks_refuse_mutation` | signed consumer receipts enforce retained proof and final database |
| `test_projected_repository_evidence_wiring_refuses_mutation` | projected repository evidence and chunked secret scan refuse mutations; the blocked-postinst fixture's 15-second deadline, <20-second runtime bound and failure diagnostic are mutation enforced |
| `test_digest_cutover_includes_nonignored_untracked_files` | digest audit includes nonignored untracked files and reviewed policy |
| `test_digest_cutover_rejects_malformed_or_overbroad_allowlist` | frozen digest inventory, typed authority, and narrow reviewed compatibility |
| `test_digest_cutover_accepts_typed_authority_and_frozen_compatibility` | frozen digest inventory, typed authority, and narrow reviewed compatibility |
| `test_docs_ignore_disposable_snapshot_payloads_not_repository_docs` | docs gate ignores disposable snapshot payloads but rejects stale repository links |
| `test_zstd_static_option_is_scoped_to_zstd_dependency` | dependency linkage and release-only static runtime metadata fail closed |
| `test_runtime_metadata_rejects_previous_dynamic_glibc_model` | dependency linkage and release-only static runtime metadata fail closed |
| `test_runtime_metadata_is_release_install_only` | dependency linkage and release-only static runtime metadata fail closed |
| `test_musl_is_in_runtime_policy_metadata` | reviewed musl toolchain, static runtime, and vulnerability dispositions are pinned |
| `test_target_apt_import_is_the_only_additional_process_and_apt_boundary` | apt import and native child-process owners retain explicit boundaries |
| `test_native_child_process_boundaries_are_explicit` | apt import and native child-process owners retain explicit boundaries |
| `test_composite_action_pin_audit_rejects_movable_refs` | commit-pinned composite actions reject floating refs |
| `test_workflows_pin_verified_ghr_zig_installation` | Zig installer must remain exact and setup-zig or cache substitutions refuse |
| `test_download_cache_uses_opaque_cli_owned_archive` | download action consumes opaque CLI-owned archive and pinned blob API |
| `test_native_download_negative_cases_require_bound_outcome_assertions` | workflow expected failures require bound outcomes, no hidden failures |
| `test_native_recovery_keeps_existing_required_checks_fail_closed` | required CI modes, architecture and aggregate failure propagation refuse mutations; core/repository and FAMILY shards require exactly one 35-minute timeout each, scenarios exactly one 75-minute timeout, with removed, altered and duplicate budgets rejected; all three Zig recovery jobs keep every mode, selector, fixture setup and aggregate binding, without a legacy or duplicate recovery suite; aggregate gate rejects all 625 combinations of success, failure, cancellation, skip and unknown job results across build and three shards |
| `test_report_path_reader_refusals_are_mutation_enforced` | report provenance readers reject unbound paths and symlinks |
| `test_recovery_gate_selector_graph_is_mutation_enforced` | complete recovery selector graph and pinned fixture handoffs refuse mutation: all nine public selectors remain exclusive, all default/parity/core and pinned-dpkg runners execute, signed fixture interpreters remain wired, repository `.tmp` is prepared, and focused options cannot narrow the aggregate |
| `test_native_core_completion_wiring_is_mutation_enforced` | core completion and ordinary recovery remain executed and bound |
| `test_native_exercise_final_matrix_and_completion_guard_are_mutation_enforced` | final recovery matrix and prior completion are mutation enforced |
| `test_native_entry_point_output_shapes_are_mutation_enforced` | recovery entry points execute expected output shape and both core CI modes; signed FAMILY CI modes are enforced by the required shard test |
| `test_native_workflow_acceptance_wiring_is_mutation_enforced` | signed FAMILY and projected workflow acceptance refuse unwired evidence; signed FAMILY allocation boundaries retain every scenario reset and long-lived receipt |
| `test_lifecycle_migration_retires_four_python_gates_without_weakening_reference_refusal` | lifecycle gates retain reference refusals and required Zig selectors |
| `test_lifecycle_migration_removes_entrypoints_and_preserves_fixture_imports` | six retired lifecycle and recovery Python entry points stay absent, fixture modules remain import-only, and remaining consumers stay wired |
| `test_build_workloads_keep_both_modes_and_all_existing_suites` | all required CI workloads and optimized-mode selections fail closed under mutation, including both-mode apt acceptance, isolated root caches, and diagnostic normalization; Debug and ReleaseSafe build workloads execute all commands and propagate failures |
| `test_install_action_reuses_pinned_bundles_and_never_short_circuits` | install action uses pinned bundles and validates before emitting result |

## Offline snapshot (`tools/test_real_snapshot_acceptance.py`)

| Previous case | Zig test (`test/real-snapshot-policy.zig`, `snapshot:` prefix) |
| --- | --- |
| `test_explicit_keyring_requires_an_absolute_regular_non_symlink_file` | explicit regular keyring rejects missing, relative, directory and symlink paths |
| `test_existing_workspace_refuses_before_cli_or_mutation` | existing directory and dangling symlink refuse before fixture CLI or mutation |
| `test_native_zero_action_update_keeps_the_installed_receipt` | offline native creation and zero-action update preserve evidence, lock usage and receipt |
| `test_dangling_workspace_symlink_refuses_before_cli_or_mutation` | existing directory and dangling symlink refuse before fixture CLI or mutation |
| `test_unreviewed_signer_refuses_before_download` | unreviewed initial signer refuses before any download |
| `test_failed_traced_refresh_still_rejects_forbidden_exec_fallback` | failed traced refresh reports freshness while no forbidden native exec occurs |
| `test_traced_candidate_rejects_a_dpkg_exec_even_on_failure` | trace rejects forbidden dpkg execve and descriptor execveat even on failed refresh |
| `test_missing_candidate_trace_refuses_even_when_command_failed` | missing trace refuses failed command and invalid-lock probe audits dpkg-deb |
| `test_invalid_lock_probe_still_audits_forbidden_exec` | missing trace refuses failed command and invalid-lock probe audits dpkg-deb |
| `test_traced_candidate_rejects_dpkg_execveat_by_descriptor` | trace rejects forbidden dpkg execve and descriptor execveat even on failed refresh |
| `test_failed_receipt_verification_refuses` | failed receipt and unreviewed update signer refuse before update |
| `test_bounded_transient_retry_logs_remain_visible` | bounded retry diagnostics remain evidence, unexpected stderr fails refresh |
| `test_unexpected_stderr_refuses_after_successful_refresh` | bounded retry diagnostics remain evidence, unexpected stderr fails refresh |
| `test_unreviewed_update_signer_refuses_before_update` | failed receipt and unreviewed update signer refuse before update |
| `test_update_status_change_refuses_zero_action_evidence` | status mutation and package-owned excluded device cannot produce zero-action evidence |
| `test_candidate_rejects_package_owned_excluded_device` | status mutation and package-owned excluded device cannot produce zero-action evidence |
| `test_reference_rejects_corrupt_cached_archive_before_creating_root` | reference rejects corrupt cached archive before creating root or snapshot |

Required snapshot policy tests drive the production scripts with an offline Zig
fixture CLI and a scoped trace stub. They never fetch a live snapshot. The
manual/scheduled real-snapshot acceptance job and native/reference comparison
remain separate from these hermetic required tests.
