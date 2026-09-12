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
debz COMMAND --install-root ROOT --cache-path CACHE --state-path STATE \
  --architecture ARCH [OPTIONS] [PACKAGES...]
```

Commands are `refresh`, `install`, `remove`, `upgrade`, `upgrade-all`,
`reinstall`, `download`, `plan`, `list-installed`, `list-available`, `info`,
`provides`, `why`, `clean`, and `recover`.

The nested `debz repo add` command is not a product API v1 operation. It uses
the separate versioned `debz.repository_api` surface documented in
[Repository management API](repository-management.md), preserving every
product API v1 request, result, schema, exit meaning, and host-root denial.

The proposed apt-shaped system facade likewise has a separate
`debz.apt_system_api` contract and trusted profile. It does not add
multi-package requests, live-root orchestration, configuration inheritance, or
new success evidence to product API v1. See
[Apt-shaped system facade contracts](apt-system-facade.md).

The nested `debz package-cache fingerprint` and `debz package-cache prepare`
commands likewise use dedicated versioned schemas rather than changing product
API v1. They expose `debz.package_cache_workflow` as a lock-oriented,
non-installing API: fingerprinting performs no repository or package I/O, and
preparation authenticates and verifies the complete lock closure. The default
`legacy_dpkg` backend retains the v1 lock, fingerprint, result, and archive
contracts. Explicit `--transaction-backend native` selects genuine v2 locks
using the core native solver-policy domain, v2 fingerprint/result schemas,
and the distinct v2 archive stream. Neither mode auto-detects the other.
The library provides corresponding typed `createNativeFingerprint`,
`preflightNative`, and `prepareNative` entry points and writer-held variants.

```sh
debz package-cache fingerprint \
  --lock-input /work/closure.lock.json \
  --cache-path /work/cache --architecture amd64 --json

debz package-cache prepare \
  --lock-input /work/closure.lock.json \
  --cache-path /work/cache --architecture amd64 \
  --source /work/repository.sources --keyring /work/archive-keyring.gpg --json

debz package-cache prepare --transaction-backend native \
  --lock-input /work/native-closure.lock.json \
  --cache-path /work/native-cache --architecture amd64 \
  --source /work/repository.sources --keyring /work/archive-keyring.gpg \
  --archive-output /work/native-closure.dbzcache --json
```

Native preparation permits empty and mixed-origin closures. Repository
packages still require matching authenticated metadata, including on cache
hits. Local artifacts must already be present in the verified CAS or imported
archive and must pass local payload, digest, size, and identity validation.
Missing local artifacts require separate explicit acquisition; corrupt local
artifacts refuse even with online repair enabled. Redacted provenance URLs
are never treated as acquisition inputs or promoted to repository authority.
Closures without repository origins require no source or keyring inputs.
Empty closures produce zero verified objects and a canonical empty v2 archive.
Repository/bootstrap workflows with other solver-policy scopes remain gated
until their own native integration.

Native keys use a separate `debz-package-cas-v2-` prefix and fingerprint
domain while retaining the shared `packages-v1/objects` layout. The download
and install actions support matching explicit native selection. Other native
consumer integrations remain separately gated.

`--restored-cache none|partial|exact` is a typed orchestration hint. The
first-party action computes it from the cache service response; it is not
caller-provided action input. An exact restore makes any missing lock object a
corruption failure unless explicit online repair is enabled.

The action pairs that hint with private `--archive-input`/`--archive-output`
paths below `RUNNER_TEMP`. The CLI owns both import and export of the
path-free `debz-package-cache-archive-v1` format. These archive paths must be
absolute, distinct, and outside the cache root; they are orchestration files,
not cache keys or public action outputs.

`debz -h` and `debz --help` print root help. Every command accepts `-h` and
`--help` after the command name and prints command-specific help without
performing validation, filesystem access, repository access, or other backend
work. Help flags take precedence over other command arguments wherever they
appear. The `package-family-capabilities` metadata command follows the same
help contract. Positional `help` is not a command or alias.

Version `0.3.0` replaces the `debz --version` flag with the `debz version`
subcommand. The removed flag is rejected as an unknown command rather than
retained as a compatibility alias.

Inputs are explicit: `--source`, `--config`, `--keyring`, `--status-path`,
`--default-release`,
`--repository-policy`, `--lock-input`, `--lock-output`, `--transaction-backend`, `--offline`,
`--proxy`, `--credential-reference`, `--cache-only`, `--recommends`,
`--allow-downgrade`, `--deadline-ms`,
`--lock-wait-ms`, `--noninteractive`, `--conffile`, and typed `--force`
policies. Paths must be absolute and traversal-free. No host APT configuration,
keyring, proxy, credential, or environment is inherited.

`install`, `remove`, `reinstall`, and `download` accept exactly one package
selector; `plan` accepts zero or one. Supplying unsupported extra selectors is
a typed usage error rather than silently ignoring them. Singleton options
cannot be repeated.

Every mutating command requires `--assume-yes`. Noninteractive transaction
commands additionally require `--conffile keep-existing` or
`--conffile use-package-version`. `plan` and `download` are non-executing.

`--transaction-backend legacy_dpkg|native` selects the core backend; omission
retains `legacy_dpkg`. Embedders select the same backend with
`ProductionBackend.transaction_backend`, without changing product API v1
request or result encoding. Experimental core native execution requires an
explicit reviewed v2 lock, confirmation, conffile policy, authenticated
repositories, and a supported non-host Linux root. The existing package-owned
`usr/bin/dpkg-trigger` target and private mount-namespace privileges are required;
missing targets refuse without placeholders. Native execution never calls the
command-shaped executor, including injected executors. There is no fallback.

Native `plan`/`download` resolve and replay exact-lock v2 from authenticated
repository evidence. They do not convert v1 locks or invent local-artifact
origins. Native solver policy uses a distinct digest domain, so locks cannot
cross backend policy boundaries. V1 remains the legacy core format; neither
backend silently accepts the other's format. Native package downloads bind
identity, repository/snapshot, SHA-256, and size before cache or transport
access, including cache-only replay. The separate `package-cache` commands
also support explicit native selection as described above; other consumer
contracts remain gated where documented.

Native execution captures the complete database and acquired archive evidence
under its caller-owned root attempt, derives trigger authority, and revalidates
the compiled program before mutation. An unchanged validated closure returns
`changed: false` without inventing an execution receipt. A terminal native
success or known failure publishes native provenance, binds outer completion
to that exact receipt, acknowledges native evidence, and only then clears the
outer record. The v1 result summary identifies the receipt digest and retained
evidence directory; it does not fabricate legacy command reports.

`recover --transaction-backend native --install-root ROOT --assume-yes`
uses the original persisted request, program, archive, policy, and helper
evidence. It accepts no replacement repository/keyring/lock inputs or force
policy and does not open cache or state directories. Native evidence always
lives under `ROOT/var/lib/debz`; `--state-path` does not relocate it. Recovery
of a known terminal failure reports exit 7 after receipt-backed cleanup;
unknown script outcomes and invalid evidence remain blocked with exit 8.
Recovered transactions report whether the original attempt reached mutation;
recovery with no outstanding execution reports `changed: false`.
The internal `ProductionBackend.executeWorkflow` seam also supports native
batch install/remove and upgrade-all, including explicit outer ownership.
Planning and execution share the same canonical selectors and genuine v2
authority. Workflow recovery supplies the original semantic operation,
selectors, and request policy (recommends, repository priority, conffile, and
downgrade settings), which must match the held original attempt; it accepts
no replacement repository, keyring, lock, or force inputs. Recovery still uses
only persisted native execution evidence. With no outstanding attempt it
reports no changes.

Native reservation binds an outer attempt before repository access; execution
must adopt the original selectors and policy rather than silently prepare a
different operation. Planning and downloading cannot acquire ownership.
An unchanged or refused pre-mutation attempt retains an abandoned owner marker
for explicit finalization without inventing a native receipt. Ordinary owned
success acknowledges native evidence before clearing the record and retaining
a released owner marker. The outer caller explicitly finalizes that marker.

Deferred recovery retains the completed record, receipt-bound completion, and
pending owner marker until the outer caller durably accepts the exact token.
Owned known failures use this same handoff while retaining exit 7 and their
failure outcome; they are not relabeled as successes. Acknowledgment verifies
the original operation, request policy, completion, native receipt, and exact
reviewed v2 owner where present. It acknowledges native evidence before clearing
the root record or owner marker, and retries do not replay package work.
Callbacks refuse physical host roots and orphan native intents, including
otherwise idempotent cleanup requests. Unresolved native programs, workspaces,
progress, script/trigger evidence, and mutation journals also prevent a
recordless callback from treating the root as clean.

Internal native clean-reconciliation claims require an independently retained
exact owner token and a root with no record, owner marker, or active native
evidence. The pre-mutation claim binds the outer generation, state, profile,
lock digest, and canonical semantic request; the post-mutation claim binds
the original execute-request digest and the outer caller's lock/evidence
digests. Reviewed claims preserve exact v2 ownership. They reserve the root
against other operations until explicit finalization, including across
interrupted publication or cleanup.

These claims protect root exclusion only. They do not verify a package
closure, publish a native completion receipt, or authorize package work; the
outer caller remains responsible for authenticating its lock and completion
evidence. Like other native recovery callbacks, they accept no replacement
repository, keyring, lock-path, or force inputs and open no cache/state paths.
The apt/system orchestrator, repository/bootstrap, package-family, and Actions
consumers remain gated until their separate native contracts are integrated.

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
published at the output path. Successful locked legacy transactions atomically publish
`transaction-result.json` under the explicit state path.

Legacy `recover` resolves an interrupted transaction. When the root's active attempt
is already `completed` and only owes provenance — a crash between the terminal
record and its published provenance — `recover` discharges that obligation
without running dpkg again: it verifies any `transaction-result.json` that
survived, publishes
`INSTALL_ROOT/var/lib/debz/root-operation-completion-v1.json`
([`schema/root-operation-completion-v1.json`](../schema/root-operation-completion-v1.json)),
binds the record to it, clears the active intent, and reports success with
`changed` true, because it published durable provenance and unblocked the root
even though no package state changed. The result item names the outcome, the
detailed-provenance classification (`already_present`, `recovered`, or
`unavailable`), the journal classification, whether the interrupted run's
recovery intent could be removed, and the statement digest. A
document that cannot be read, decoded, or bound to the interrupted attempt
leaves the root blocked with exit 8 and a diagnostic naming the document to
inspect; nothing is published or cleared. A mutating command run against such a
root is refused with exit 8 and a diagnostic naming `debz recover`. See
[root-scoped operation coordination](root-operation.md).

`debz transaction-result verify --state-path PATH --lock-input PATH
--architecture ARCH --json` is the read-only action handoff for that combined
document. It opens the state directory and result without following symbolic
links, validates canonical encoding and digest, requires a successful exact
final verification, compares repository/package/request/policy evidence with
the canonical lock, and emits the bounded
`io.github.cataggar.debz.transaction-result-summary.v1` summary. This allows an
unprivileged action process to verify a result written by an explicitly
elevated `debz` process without granting a second program sudo access.

Native callers explicitly select a separate receipt-backed handoff:

```sh
debz transaction-result capabilities --transaction-backend native --json
debz transaction-result verify --transaction-backend native \
  --install-root /explicit/root --lock-input /explicit/closure.v2.json \
  --architecture amd64 --json
```

The capability response declares `native-transaction-result-v1` and the exact
native summary/receipt/completion/lock contracts before a caller attempts a
mutation. It requires no root access. Native verification accepts no
`--state-path`, never autodetects a legacy result, and emits
[`transaction-result-summary.v2`](../schema/transaction-result-summary-v2.json).
The underlying native receipt and root-operation completion remain their
existing v1 schemas; they are not converted into command-oriented provenance.

Verification acquires the existing root-operation lock without creating a
namespace, lock file, or attempt. It requires a physically bound alternate
root with no active native evidence, root attempt, or outstanding owner
marker. It checks canonical completion and receipt digests, retained evidence
bytes, original caller/program/authorization bindings, the exact v2 closure
and origin evidence, terminal success, and the current package-database
generation and final state. The summary preserves the lock's request/solver
policy domains separately from the original caller's request/policy domains.
Empty installed closures may retain only their authorized residual
configuration records.

Missing, stale, incomplete, failed, or mismatched evidence refuses with exit 7
and no success summary. Verification never repairs, acknowledges, clears, or
replays anything and does not invoke a helper or maintainer script. A
receiptless unchanged closure is not proof that a native transaction occurred.

### Receipt-bound native install handoff

`debz transaction-result capabilities --transaction-backend native --for-install
--json` advertises `native-install-v1` without root access or mutation, separately
from the read-only verification capability above.

An explicitly locked `debz install --transaction-backend native --native-result
--json ...` returns `io.github.cataggar.debz.native-install-result.v1` on success.
This envelope contains the unchanged command.v1 result and typed native evidence:
root, architecture, lock digest, original caller request/policy digests, exact
closure count, and a nullable receipt binding. Changed installs bind the actual
receipt, root completion, and program digests captured by the completing native
caller. Consumers compare them to the read-only verifier's v2 summary; human
summary strings are not a machine interface.

An unchanged result carries no receipt. Native preparation has verified the
unchanged database closure under the root lock, but no native execution is
claimed. The install action reports `changed: false` and empty receipt/provenance
paths rather than relabeling an older receipt or requiring one for an unchanged
result. This does not change solver behavior: an explicit install selector can
still select a reinstall on an already-installed root.

The opt-in result mode is rejected for legacy, unlocked, non-install, or non-JSON
requests before backend execution. Ordinary command.v1 output and structured
failure output are unchanged. Schemas:
[`native-install-result-v1.json`](../schema/native-install-result-v1.json) and
[`native-install-capability-v1.json`](../schema/native-install-capability-v1.json).

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

Package-cache JSON schemas are:

- [`package-cache-fingerprint-v1.json`](../schema/package-cache-fingerprint-v1.json)
- [`package-cache-fingerprint-v2.json`](../schema/package-cache-fingerprint-v2.json)
- [`package-cache-result-v1.json`](../schema/package-cache-result-v1.json)
- [`package-cache-result-v2.json`](../schema/package-cache-result-v2.json)
- [`package-cache-error-v1.json`](../schema/package-cache-error-v1.json)

Their successful outputs include the canonical lock digest, CLI-owned
fingerprint, exact/compatible cache keys or verified preparation counts, and
the exact `packages-v1/objects` path. Fingerprint output also supplies the
maximum opaque archive byte count for a bounded pre-import download. Error
documents contain no cache key or success-shaped path. The error v1 envelope
is backend-neutral and remains shared by both modes.

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
