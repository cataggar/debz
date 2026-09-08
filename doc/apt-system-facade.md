# Apt-shaped system facade contracts

`debz.apt_system_api` is a separate versioned orchestration contract for the
deliberately limited `debz apt` interface. `debz.apt_system_cli`
defines its pure parsing, help, rendering, and confirmation-decision contract.
`debz.apt_system_orchestrator` implements the reusable profile-bound engine
behind that contract, and `debz.apt_system_command` connects the strict parser
to that engine. Product API v1 and its existing commands remain unchanged. The
pure parser still performs no dependency-solver, namespace, live-root,
terminal, or production orchestration work.

The interface is **apt-shaped, not apt-compatible**. It promises no apt output,
wording, exit-code convention, option aliases, configuration discovery, or
dependency-resolution edge behavior. There is no `apt-get` alias and no
passthrough to apt or dpkg. Unsupported syntax must become a typed usage
outcome before repository, root, or package mutation.

## Strict CLI grammar

The accepted grammar, and no other apt spelling, is:

```text
debz apt update
debz apt install [-y] PACKAGE...
debz apt remove [-y] PACKAGE...
debz apt upgrade [-y]
debz apt list --installed
```

The two facade-wide options have one canonical placement:

```text
debz apt [--profile PATH] [--json] COMMAND ...
```

They may appear in either order, once each, only after `apt` and before the
command. The default profile is exactly `/etc/debz/default.json`. `-y` is
accepted only where shown and must precede package operands. Package tokens
beginning with `-`, duplicate packages, extra or missing operands, duplicate
singleton options, other list modes, `apt-get`, `--` passthrough, and every
undocumented apt command or option are typed usage failures. Usage rendering
never reflects rejected command, option, credential, control, or invalid UTF-8
bytes back to the terminal.

`debz apt` and `debz apt -h`/`--help` select root apt help. For a recognized
subcommand, `-h`/`--help` wins over malformed trailing arguments before any
parsing work that could lead to I/O. Help attached to an unknown command does
not turn that command into a valid topic.

The parser has bounded argument, package, path, and token limits. It allocates
nothing, reads no profile or environment state, and performs no filesystem,
repository, root, mount, terminal, or backend I/O. Accepted commands contain
the resolved profile path, human/JSON output choice, `assume_yes`, the
`apt_system_api.Operation`, package slice, and validated canonical request
digest. No ambient proxy, configuration, credential, or keyring is injected.

Human rendering identifies itself as apt-shaped and not apt-compatible,
preserves the complete result summary used for plan/change details, and prints
all profile and operation evidence paths and digests present in
`apt_system_api.Result`. Typed human failures go to stderr. JSON rendering
writes exactly one canonical apt-system result document to stdout and never
prompts.

The exported confirmation seam deliberately performs no terminal calls.
Non-`-y` mutation requests wait until a plan exists. A human request may then
ask the executable integration for confirmation only when its input, plan
output, and diagnostic streams are terminals. The complete atomic plan and
exact-lock path are printed and flushed first. A negative answer, EOF, or
non-TTY returns a typed
`confirmation_required` result without executing. A JSON request instead
returns one canonical result-v2 document containing the reviewed change items
and can never prompt. Result-v2 item arrays are allowed only for
`list_installed` results and mutating `confirmation_required` reviews. `-y` is
solely the caller's confirmation signal; profile conffile policy is unchanged.

System recovery has the separate strict spelling:

```text
debz recover [--json] --system-profile PATH
```

Human recovery prepares and renders the retained exact action before the same
TTY-only confirmation. JSON recovery prepares but never prompts or mutates.
Malformed recovery syntax is rejected before profile or operation-state I/O.
Parse failures carry the output mode recognized from the valid canonical
option prefix. Rejected command arguments, misplaced `--json`, and a
`--json` token consumed as an invalid profile value cannot switch rendering.
Decisive help for a recognized command returns before counting or inspecting
the ignored suffix.

## Trusted system profile

The default profile path is `/etc/debz/default.json`; its strict schema is
[`system-profile-v1.json`](../schema/system-profile-v1.json). Version 1 carries:

- one or more explicit repository source descriptors and optional paired debz
  repository configuration descriptors;
- explicit keyring paths;
- the native and foreign architectures;
- `strict_priority` or `best_version` repository policy;
- cache and state paths, defaulting only to `/var/cache/debz` and
  `/var/lib/debz`;
- the default `keep_existing` or `use_package_version` conffile behavior; and
- nullable, explicit proxy URL and credential-reference fields.

Proxy URLs require the canonical lowercase `http` or `https` scheme. Null or
omitted proxy and credential fields mean disabled. They never mean
"read apt.conf", "inspect the environment", or "discover credentials".
Likewise, the loader never consults `/etc/apt`, ambient keyrings, GnuPG
configuration, dpkg configuration, or process environment settings.

`system_profile.load` takes an injected filesystem interface. The profile and
every source, config, keyring, and credential file are bounded and must be a
canonical absolute non-root path. Every ancestor directory is opened without
following symbolic links and must be root-owned and not group- or
world-writable. On Linux the leaf is first opened with `O_PATH | O_NOFOLLOW |
O_CLOEXEC` and classified without opening the underlying object for I/O. Only
a validated regular file is then opened read-only; its device and inode must
match the `O_PATH` descriptor before any read. FIFO, device, and other special
files therefore fail before an I/O-capable open. Platforms that cannot model
ownership fail closed. Tests inject file and ancestor metadata and do not
require root.

Profiles reject unknown JSON fields, duplicate repositories, keyrings or
foreign architectures, credential-bearing proxy URLs, invalid architectures,
unsafe paths, excessive bytes, and excessive object counts. The loaded profile
records SHA-256 of the exact reviewed profile bytes plus path-, role-, content-,
and descriptor-identity evidence for every referenced file. Later consumers
must call `readTrustedFile`/`readVerified`, which reopens without following
links, revalidates every ancestor, and requires both identity and content to
match. Credential bytes are never retained in profile or state evidence.

Example:

```json
{
  "schema": "https://debz.dev/schema/system-profile-v1",
  "version": 1,
  "repositories": [
    {
      "source_path": "/etc/debz/debian.sources",
      "config_path": "/etc/debz/debian.json"
    }
  ],
  "keyring_paths": [
    "/usr/share/keyrings/debian-archive-keyring.gpg"
  ],
  "architecture": "amd64",
  "foreign_architectures": ["i386"],
  "repository_policy": "strict_priority",
  "cache_path": "/var/cache/debz",
  "state_path": "/var/lib/debz",
  "default_conffile": "keep_existing",
  "network": {
    "proxy_url": null,
    "credential_reference": null
  }
}
```

## Request and result

[`apt-system-request-v1.json`](../schema/apt-system-request-v1.json) covers only
`update`, multi-package `install`, multi-package `remove`, `upgrade`, and
`list_installed`. A multi-package request is one bounded request with one
digest; it is not a sequence of singleton product API calls.

[`apt-system-result-v1.json`](../schema/apt-system-result-v1.json) has stable
`success`, `usage`, `configuration`, `authentication`, `planning`, `download`,
`transaction`, `recovery`, and `internal` outcomes. Diagnostics carry a stable
identifier and the same outcome classification. Human summary text is not a
machine interface. Itemless results retain the exact v1 wire format and digest.
[`apt-system-result-v2.json`](../schema/apt-system-result-v2.json) is the
explicit additive result extension used when `list_installed` returns a
non-empty bounded, owned `items` array preserving each package name and
optional version, architecture, and detail. It keeps apt-system API version 1;
no v1 document is emitted with a field that old v1 validators reject. Other
operations cannot expose items, and v2 items participate in the canonical
result digest. Runtime validation also measures the complete canonical
encoding and rejects any result over the 256 KiB document ceiling, even when
every individual item and the item count are otherwise valid.
Production refresh repository-detail items are validated at the product
boundary but intentionally not projected into the apt-system `update` result.

Every result binds the canonical request digest. `apt_system_api.execute`
rejects any backend result whose operation or request digest differs from the
submitted request, whose shape is invalid, or whose canonical result digest is
wrong. An envelope rejected before it can be canonicalized instead carries the
SHA-256 of the fixed label
`debz:apt-system-api-v1:rejected-unbound-request`; no rejected path, package,
or other unbounded input is traversed or hashed. Once a profile is loaded the
result also binds the profile path,
exact-byte digest, and aggregate reference-evidence digest. Successful package
mutation is impossible to represent without all of:

- the canonical exact-lock path, schema version, and digest;
- the retained exact-lock-bound transaction or recovery-discharge evidence
  path, schema version, and digest; and
- root-operation completion path, schema version, digest, and completed
  attempt identifier.

These are evidence bindings, not claims that orchestration happened. A future
implementation must validate the referenced documents through their existing
modules before constructing success.

## Durable active operation

[`apt-system-operation-state-v1.json`](../schema/apt-system-operation-state-v1.json)
and `debz.apt_system_state` define a bounded, canonical, digest-bearing active
operation record. It binds attempt and generation, operation, request, profile
and reference evidence, exact lock, transaction result, root-operation
completion, mutation evidence, phase, outcome, timestamp, and diagnostic.
Pre-mutation phases require `mutation_started=false`; mutating, verifying,
recovery-required, and recovering phases require it to remain true. Exact-lock,
transaction-result, and completion evidence appear only at their defined
boundaries and can never be removed or changed by a later generation.

The store takes an operation lock, rereads the current canonical state, and
compares attempt ID, generation, and digest before every transition. The next
generation must be exactly one greater and follow the legal phase graph.
Publication uses a writer-unique mode-0600 staged file with file and directory
sync around atomic rename. Directory durability uses a separate sync-capable
descriptor rather than the path-only handle used for relative operations. An
error reported after rename means the new state may already be visible and
must be reconciled by rereading it. Stale and concurrent writers fail rather
than overwrite evidence, and no transition is possible from completed state
or backwards out of recovery evidence.

The state cannot call a package mutation successful or recovered without the
same lock, transaction, and root-completion evidence required by the result.
Once mutation has started, failure remains distinguishable from a
pre-mutation failure and the `recovery_required` phase cannot be represented as
safe abandonment.

## Orchestration engine

The engine separates `prepare` from confirmed `execute`. Update and
list-installed requests route directly through the injected private-live-root
runner. Install, remove, and upgrade-all preparation instead:

1. loads the explicitly requested strict profile and revalidates every bound
   source, config, keyring, and credential reference;
2. rejects an outer or lower-level post-mutation active operation before
   repository work, while a CAS-proven outer pre-mutation or completed record
   is retained and reconciled;
3. reserves one durable operation directory under
   `STATE/apt/operations/ATTEMPT`;
4. submits every selector in one `ProductionWorkflow` plan-only request;
5. retains and validates one canonical `exact-lock-v1.json`; and
6. returns the complete backend change set for rendering and review.

Preparation never executes a package transaction. The caller can render the
review and either pass explicit confirmation to `execute` or return the
versioned `confirmation_required` result. `-y` is therefore only a caller
confirmation source; execution always takes conffile behavior from the loaded
profile.

Confirmed execution reloads and revalidates the profile, rereads the active
state with locked compare-and-set, revalidates the full exact-lock binding
immediately before acquisition and again immediately before mutation, and
first invokes an internal reservation mode that durably binds the outer
attempt identity under the lower root-operation lock without repository or
package mutation. The outer state remains `downloaded` until that reservation
returns. It is then advanced to `mutating` and `ProductionWorkflow` execute
acquires the locked package closure with the same selectors and exact lock. A
valid but different replacement is rejected, not merely a malformed lock. The
only install-root spelling supplied to a backend is
`live_root.logical_root_path`; `/` remains denied by product API v1 and
`live_root.host_root_allowed` remains false. Root, runtime, lock, or mountpoint
replacement is surfaced as a typed conflict.

If confirmed execution returns an unexpected transport, verification,
publication, durability, CAS, or acknowledgment error, the CLI does not infer
that mutation was absent. It asks the engine to inspect the exact active state
while holding the state lock and emits an owned recovery result carrying the
profile, exact lock, active-state path, and any retained transaction or
completion evidence. A mutation-started state is rendered with `changed=true`
and the exact `debz recover --system-profile PATH` action. The same
reconciliation applies to errors during confirmed recovery.

The trusted profile-reference lease is revalidated immediately before every
read-only route and every plan, download, execute, and recovery workflow call.
It is revalidated again after download before execution and before retained
recovery evidence is reconciled. Replacement between any two calls therefore
prevents the later call; in particular, replacement after download produces
zero execute calls.

`PrivateLiveRootRunner` is the production composition's concrete runner. It
blocks the live-root supervisor's watched signals before creating a transport
reader, so every helper inherits the mask, then invokes the pre-blocked
`live_root` entry point and restores the caller's original mask only after the
reader and privileged process have terminated. It drains a bounded pipe
concurrently and accepts only a canonical product-result document whose
operation matches the workflow surface: plan-only is `plan`, download-only is
`download`, execute is the semantic package operation, and recovery is
`recover`.
Termination, namespace setup, identity replacement, cleanup, transport, and
lower-level root-operation status failures remain typed at the runner boundary.
Owned results, including failure summaries and diagnostics, and list items are
copied into the parent before namespace cleanup. Capability-gated integration
tests exercise read-only routing and every workflow mode through the real
root-mapped namespace path.

The system state-store adapter creates and opens every directory component
without following symbolic links. Request, retained state, exact lock,
transaction result, and completion evidence stay on the profile state
filesystem. Publication uses mode-restricted staged files, file sync,
same-directory atomic rename, directory sync, and operation locks. Every newly
created hierarchy component is made durable by syncing its containing parent
through a normal sync-capable directory descriptor. In particular, the
`operations` directory is synced immediately after creating an attempt
directory, and request evidence is synced before active-state publication can
begin. A sync error therefore leaves no active pointer to an operation
directory that may disappear after power loss. Completed operation directories
are retained as history while the active record is
removed only after the final state is durable. A crash before removal therefore
leaves a deterministic active or completed record rather than an ambiguous
symlink or cross-filesystem pointer. If the retained final state was published
but active-state compare-and-set was interrupted, retry strictly decodes that
immutable document and verifies an outcome-specific evidence matrix before
advancing and clearing the matching active state with the retained generation,
timestamp, and diagnostic. A pre-mutation failure must match the exact
attempt, request, profile, and optional plan/lock evidence inherited from its
failure phase, while transaction and root-completion evidence must both be
absent. A post-mutation failure requires its exact lock and transaction result
but forbids success completion evidence. Successful and recovered mutating
outcomes continue to require matching lock, transaction, and completion
bindings; non-mutating terminal outcomes forbid all three. Retry adopts the
exact first retained document rather than regenerating volatile terminal
fields. Stale, foreign, or outcome-incompatible retained state fails closed.

After a successful backend return, `SystemResultVerifier` rereads the canonical
exact lock and validates `transaction-result.json` through
`transaction_result_summary.verify` and transaction-provenance v1. Only then
does the store retain the transaction document and publish
`apt-system-execution-completion-v1`. This ordinary completion schema is
deliberately distinct from the recovery-only
`root-operation-completion-v1.json` discharge statement. Apt/system success is
published only after the exact lock, verified transaction result, completed
root-operation status, and final state all agree.

`prepareRecovery` reloads the same profile, retained canonical request, active
state, and exact lock. Profile, request, selector, attempt, state, or evidence
mismatches fail closed. A recoverable plan reports the stable action
`debz recover --system-profile PATH`; confirmed `executeRecovery` reconstructs
the original semantic `ProductionWorkflow` recovery request, rechecks the full
lock binding immediately before recovery mutation, and verifies and retains its
result through the same boundaries. Recovery first inspects the retained
lower-level root-operation state. A completed record with pending provenance
is routed through `ProductionWorkflow` recovery to
`dischargeOwedProvenance` without replaying package mutation. Ordinary product
recovery still clears the record on success. The internal apt/system workflow
instead supplies its outer attempt identity to the reservation call. While the
root-operation lock is held, before publishing the lower record and before
preflight can enter a mutation bridge, the workflow publishes an exact
root-local `root-operation-deferred-ack-v1.json` marker in the `bound` state.
This binds the lower attempt to the originating outer apt/system attempt before
mutation; a different prepared operation cannot adopt or replace it, even when
its semantic request and exact lock are identical. A process death immediately
after lower lock acquisition but before marker publication leaves the durable
outer state in `downloaded`, so exact-owner recovery can repeat reservation
without claiming that mutation began.

If recovery must discharge owed provenance, it may only atomically transition
that exact binding to `pending`, adding the completion and provenance digests
without changing its owner. The pending marker makes the otherwise clearable
completed/published record non-reclaimable by every ordinary mutation or
recovery, including a request using a different profile or state path.
Ordinary non-orchestrated product success keeps its existing clear-on-success
behavior. Orchestrated success instead transitions its binding to `released`,
clears and fsyncs the root record, and returns the exact attempt, marker digest,
and outer acknowledgment identity while retaining the marker. The outer engine
verifies and durably retains transaction evidence and the exact canonical lower
marker as operation-local `lower-acknowledgment-v1.json`. It then publishes the
outer completion, publishes the immutable retained final state, and CASes the
active state to that exact completed outcome before compare-and-clearing the
matching released marker. Before the active-state CAS, recovery holds the
operation lock, reopens the retained-final document without following links,
decodes and compares its exact digest and bindings on that descriptor, fsyncs
the file, then fsyncs its operation directory and durable attempt parent. That
same operation lock remains continuously held through the descriptor
revalidation immediately before CAS, active-state CAS, and active-state
durability barrier. The enforced nesting order is operation lock before
active-state lock; no active-state-locked path acquires an operation lock. A
rename-visible retained final whose directory sync failed therefore cannot
authorize active commit or lower acknowledgment. A visible matching active
document is likewise not by itself proof of durable commit: recovery reopens
and syncs the exact active file and its parent directory while holding the
state lock, even when generation and digest already equal the retained final
state. The completed active owner remains discoverable until acknowledgment
finishes. A crash before the outer commit therefore
leaves the root protected; a crash after commit but before acknowledgment
replays the retained token idempotently; a crash after acknowledgment only
clears the already committed active owner and cannot regenerate or reinterpret
the old success after a later root mutation. A proven pre-mutation failure
instead transitions to `abandoned`, clears and fsyncs the record, and
deliberately retains that terminal exact-owner marker. On retry, the old marker
remains continuously durable until it is atomically replaced by a fresh
`bound` attempt; no crash prefix exposes an unowned clean root. Legacy
record-only states retain their existing conservative recovery rules, and
absence of both documents is the only fully clean state.

The same centralized owner-aware terminalization primitive is used by normal
finish, error/deinit abandonment, explicit ownership finalization, and
deferred acknowledgment. It verifies owner and lower attempt under the root
lock, transitions the binding to its terminal state, clears and fsyncs the
record, and reopens the store to prove record absence. Completed cleanup then
compare-and-unlinks and fsyncs the binding; pre-mutation abandonment retains it
for atomic retry rotation. A binding-only residue is valid both before initial
record publication and after terminal record removal; foreign callers cannot
remove or replace it. A newly observed record without a binding is never
created by the orchestrated path and fails closed, while documented ordinary
product legacy recovery remains separate.

After a real lower recovery, the engine strictly decodes and retains the
operation-local `root-operation-completion-v1.json`, checks the observed lower
attempt ID, semantic request, architecture, exact-lock schema/version/digest,
operation, outcome, and recovery discharge, then CAS-publishes that exact
binding together with the immutable final outcome before explicitly
acknowledging the exact lower token and clearing its record and marker. The
retained-final path reopens and hashes the operation-local evidence before
that commit and acknowledgment. Ordinary success is reverified through the
transaction-result verifier against the exact lock; recovered success decodes
the retained recovery-completion document and rechecks its completed attempt,
provenance status and digest, original and discharge request domains, lock,
profile, outer acknowledgment identity, and operation-local path. Missing,
corrupt, replaced, or foreign evidence leaves the lower marker in place.
Only after evidence reverification and the active-state durability barrier
both succeed may acknowledgment proceed. The
same operation-local lower acknowledgment document is used when detailed
transaction provenance is honestly unavailable. A crash before outer commit
therefore leaves the lower completed/published record available for retry; a
crash after commit but before acknowledgment uses the retained binding and
token and idempotently clears; a crash after acknowledgment performs no later
success publication and only retires the committed active owner.
If the lower marker is absent, acknowledgment is idempotently complete only
when the lower backend acquires the root-operation lock and proves both marker
and record are absent. Marker absence with any prepared, mutating, completed,
recovery-required, legacy, or unreadable record fails closed without clearing
the outer active state or changing the lower record.
The acknowledgment rereads the marker, record, and global completion under the
root-operation lock and first durably transitions the exact marker to
`acknowledged`. It then clears the matching record and marker. A crash between
those cleanup steps is idempotent: only an exact acknowledged marker may
finish cleanup, while a pending marker remains non-reclaimable. Any attempt,
completion, provenance, outer acknowledgment identity, request, operation, or
exact-lock mismatch is rejected before clearing. Transport and signal
interruption follow the same path because the lower record cannot be reclaimed
before durable acknowledgment.
Both an originally recovered transaction and an originally successful
transaction whose provenance discharge was interrupted are accepted without a
lower workflow replay, recovery request, or fabricated transaction result. It
never infers recovery from the outer phase or accepts a global completion that
may belong to an older identical request. Without either durable binding,
an unlocked clean inspection is only advisory. Clean reconciliation reopens
ordinary exact-lock-bound transaction evidence, then calls an internal lower
reservation that acquires the root-operation lock, proves both marker and
record absent, and durably publishes an exact-owner `released` reconciliation
marker before releasing the lock. The marker attempt binds the outer attempt,
semantic execute request, exact-lock digest, and evidence digest. If an
ordinary mutation wins the lower lock, reconciliation fails closed and keeps
the outer active state; if reconciliation wins, later mutations remain blocked
until the normal verify, retain, commit, and exact acknowledgment sequence
finishes. No mutating or recovery completion clears outer state from a null or
unlocked lower proof. Clean reconciliation does not claim that lower recovery
occurred. The root record request digest is
checked against the original execute-mode production
product request, the discharge digest against the recover-mode production
product request, and the exact lock's request digest against the separately
computed semantic transaction request. These digest domains are never
substituted for one another. The
discharge can truthfully classify detailed transaction provenance as
unavailable when publication was the interrupted boundary; it does not
fabricate a transaction result. Crashes at every outer post-backend boundary
converge through this reconciliation path exactly once, while canonical or
binding mismatches remain recovery-required.

Profile loading, live-root execution, workflow backend, state store,
confirmation, result verifier, clock, and attempt-ID generation are explicit
dependencies. Hermetic tests use injected fakes plus production-created
root-operation evidence; capability-gated tests exercise the durable system
store's real publication and crash-reconciliation path. The reusable
production adapters cover the strict profile loader, `ProductionWorkflow`,
durable system store, and lock/provenance verifier. Only the capability-gated
private-runner integration test enters the real namespace supervisor; it skips
when the required Linux root namespace capabilities are unavailable.
