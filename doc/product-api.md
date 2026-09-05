# Stable product API and CLI contract

The versioned façade is `debz.product_api`. Callers construct a
`product_api.Request`, provide all `CommonOptions`, and call
`debz.executeProductRequest` with an injected `ProductBackend`. The exported
`ProductionBackend` is the concrete composition of authenticated refresh,
parsed dpkg state,
deterministic planning, verified acquisition, payload validation, transaction
execution/recovery, locks, and provenance. This keeps CLI parsing out of
embedders while preserving an injectable backend and process-runner seam for
hermetic tests.

API version 1 includes every operation in the CLI vocabulary. Backends return a
`ProductResult`; a backend that cannot perform an operation must return a
nonzero result with a stable diagnostic and must never return a success-shaped
placeholder. Tests can inject the same backend used by production callers.

## CLI

```
debz COMMAND [TARGET OPTIONS] [OPTIONS] [PACKAGES...]
```

Commands are `refresh`, `install`, `remove`, `upgrade`, `upgrade-all`,
`reinstall`, `download`, `plan`, `list-installed`, `list-available`, `info`,
`provides`, `why`, `clean`, and `recover`.

The nested `debz repo add` command is not a product API v1 operation. It uses
the separate versioned `debz.repository_api` surface documented in
[Repository management API](repository-management.md), preserving every
product API v1 request, result, schema, exit meaning, and host-root denial.

`debz -h` and `debz --help` print root help. Every command accepts `-h` and
`--help` after the command name and prints command-specific help without
performing validation, filesystem access, repository access, or other backend
work. Help flags take precedence over other command arguments wherever they
appear. The `package-family-capabilities` metadata command follows the same
help contract. Positional `help` is not a command or alias.

Version `0.3.0` replaces the `debz --version` flag with the `debz version`
subcommand. The removed flag is rejected as an unknown command rather than
retained as a compatibility alias.

The embeddable product API v1 remains fully explicit. The standalone CLI adds
a typed system profile: omitted target options select `/`,
`/var/cache/debz`, `/var/lib/debz`, `/var/lib/debz/locks`, target dpkg native
architecture, and the active root-scoped repository snapshot written by
`debz repo add`. Explicit `--source`/`--config`/`--keyring` inputs continue to
select the legacy explicit path; they are never merged with the active
snapshot. Alternate roots resolve defaults beneath that root and never import
configuration from `/`.

Explicit inputs include `--source`, `--config`, `--keyring`, `--status-path`,
`--default-release`,
`--repository-policy`, `--lock-input`, `--lock-output`, `--offline`,
`--proxy`, `--credential-reference`, `--cache-only`, `--recommends`,
`--allow-downgrade`, `--deadline-ms`,
`--lock-wait-ms`, `--noninteractive`, `--conffile`, and typed `--force`
policies. Paths must be absolute and traversal-free. No host APT configuration,
keyring, proxy, credential, or environment is inherited.

`install`, `remove`, `reinstall`, and `download` accept exactly one package
selector; `plan` accepts zero or one. Supplying unsupported extra selectors is
a typed usage error rather than silently ignoring them. Singleton options
cannot be repeated.

Explicit/embedding mutations require `--assume-yes`. A standalone system
mutation treats the subcommand itself as authorization, uses fixed
noninteractive execution and `keep-existing` conffile handling, and permits
host `/` only through this typed profile. Noninteractive explicit transaction
commands additionally require `--conffile keep-existing` or
`--conffile use-package-version`. `plan` and `download` are non-executing.

The standalone binary instantiates `ProductionBackend`. A non-mutating `plan`
or `download` may use `--lock-output` without `--lock-input` to resolve an
initial canonical lock from authenticated metadata and an empty installed
package database. Mutating operations never gain this exception and
package-family create/update requests require the reviewed lock as input.
Missing repository,
keyring, status, confirmation, conffile, or exact-lock inputs are reported as
typed errors for the affected command; there is no global backend-unavailable
result. Exact-lock input is enforced by planning, acquisition, and execution.
When both lock options are supplied, the validated input is atomically
published at the output path. For a system install without `--lock-input`, the backend creates an exact-lock
v2 for every archive-producing action plus a system-operation-lock v2 that
binds the complete canonical plan, including removals, request digest, solver
policy, executor policy, canonical install/state roots, attempt identity,
repository freshness evidence, and optional package-lock digest. The operation
lock is atomically published beneath
`INSTALL_ROOT/var/lib/debz/locks/<digest>.json` before dpkg.
Per-operation evidence under `STATE/transactions/<attempt-id>/` retains the
canonical transaction-plan-v3, package lock when present, journal, recovery
intent, and provenance. The additive v1 result `paths` object reports the
operation lock, available transaction-result-v3 provenance, and recovery path
on success and on failures after lock publication. Explicit
`plan --lock-output` followed by `install --lock-input` remains unchanged.

The active configuration's validated foreign architectures are passed to the
solver together with its native architecture. Callers cannot mix standalone
active-configuration resolution with an unrelated explicit foreign-
architecture list.

## JSON and compatibility

`--json` writes exactly one canonical result object to stdout. Diagnostics and
human failures go to stderr; human successes go to stdout. The v1 schema is
[`schema/command-result-v1.json`](../schema/command-result-v1.json). Consumers
must ignore unknown object fields. Removing or changing a required field,
operation, exit meaning, or stable error identifier requires a new schema/API
version. Additive optional fields are compatible.

Exit codes are 0 success, 2 usage/confirmation, 3 unavailable configuration,
4 authentication, 5 planning, 6 download, 7 transaction, 8 recovery, and 70
internal error. Human wording and formatting are not machine interfaces.
There is no promise of APT output, wording, or option-spelling compatibility.

Credentials must not be placed in diagnostics. `product_api.redact` removes
URI user information before provenance or output is constructed.

`--source` accepts an explicit `.list` or `.sources` file. Every enabled entry
must declare `Signed-By`, and each referenced keyring must also be declared by
`--keyring`. A `--config` file is strict JSON containing `source_path` and
optional `priority`, `default_release`, and `immutable` fields. Installed state
comes from `--status-path`, or from
`INSTALL_ROOT/var/lib/dpkg/status` when the explicit status path is omitted.
`--credential-reference` is an absolute path to a bounded file containing the
HTTP Authorization value; it is never copied into diagnostics or provenance.
One credential reference is restricted to the single normalized HTTP(S)
origin shared by all configured repositories. `--status-path` is read-only;
mutating commands always verify `INSTALL_ROOT/var/lib/dpkg/status`.
No host APT, GnuPG, proxy, credential, or dpkg configuration is consulted.
Moving repositories require `Valid-Until`. An explicit immutable repository
configuration may accept a signed Release without that field because the URI
itself is pinned; signature, Release date, identity, and all index digests
remain mandatory.
