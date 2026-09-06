# Native transaction program v1

The native transaction program is the complete low-level transaction the native
engine executes against one root. It is compiled once, before any mutation,
from evidence that has already been reviewed and validated, and it is the
durable authority for both execution and recovery.

`debz.native_program` owns the model, the compiler, the canonical document, and
the strict decoder. Compilation is pure: it reads no filesystem, opens no
package database, downloads nothing, and runs no maintainer script.

## Inputs

Compilation consumes exactly four kinds of evidence plus explicit policy:

| Input | Meaning |
|---|---|
| `authorization` | The reviewed [native transaction authorization](exact-locks-and-provenance.md), which binds the backend, exact closure lock v2 generation, request/solver-policy/executor-policy/plan digests, install root and root identity, target and foreign architectures, mutation policy, every ordered action, and the exact intended final closure. |
| `ordered_actions` | The reviewed plan's ordered lifecycle: bootstrap extraction, removals, purges, unpacks, and configure barriers. |
| `installed` | The consumed installed-database generation: its digest plus, per package, the recorded version, state, hold, essential flag, owned-path set digest, maintainer-script digests, conffile records with their recorded and observed digests, and trigger declarations. |
| `archives` | One validated archive per archive-producing action: identity, digest, size, authenticated origin, application-inventory digest, maintainer-script digests, packaged conffiles, trigger declarations, and `Replaces` names. |

Preflight also supplies the ownership conflicts it found and any root feature it
classified as outside the v1 contract. Both fail closed unless the reviewed
policy explicitly resolves them.

These input types are the adaptor contract for the package-database and archive
application modules. Those modules may produce the evidence; they cannot relax
what the compiler validates, because the compiler revalidates every
relationship between the four inputs independently.

## Output

A program binds the authorization digest, backend, install root and root
identity, target and foreign architectures, exact-lock generation and digest,
request/solver-policy/executor-policy/plan digests, mutation policy,
maintainer-script environment-policy identity, the consumed database generation
and an evidence digest over the complete installed state, every artifact with
its identity, origin, digest, size, and application digest, the intended final
closure digest, and the ordered steps with their own digest.

Every step carries a dense sequence, an explicit phase (`preflight`,
`bootstrap`, `remove`, `unpack`, `configure`, `trigger`, `verify`), an explicit
typed operation, and the sequences of the steps it requires. Required sequences
are always strictly smaller, so the step graph is acyclic and an interrupted
transaction can be resumed or refused deterministically.

Operations are typed, never opaque:

- preflight assertions for the authorization, root identity, database
  generation, each affected package's installed state or absence, and each path
  ownership conflict with its resolution;
- artifact revalidation, bound to the archive digest, size, and application
  digest;
- filesystem intents: essential bootstrap materialization, unpack, owned-file
  removal, and purge, expressed as typed forward references to the artifact
  application digest and the published ownership-set digest rather than as an
  unvalidated instruction list;
- maintainer-script calls with the script source (installed or new package),
  exact script digest, exact argument vector, environment-policy digest, the
  package state a failure records, whether the failure requires durable
  recovery, and the exact compensating unwind call where dpkg defines one;
- conffile decisions with the packaged, recorded, and observed digests, the
  reviewed policy, and the resulting compatible action;
- trigger interest records, activations with their interested packages and await
  semantics, and one deferred processing barrier followed by the exact
  `postinst triggered` calls;
- database state records for every transition, database publication, final
  state verification, and the provenance the transaction must publish.

No step contains a shell command, and no step is a free-form escape hatch.

## Lifecycle modeling

The compiler expands the authorized actions into dpkg-compatible transitions:

- fresh install: `preinst install`, unpack, conffile decisions, `unpacked`,
  configure barrier, `postinst configure`, `installed`;
- install over `config-files`: the recorded version is replayed as the
  `install` and `configure` argument;
- upgrade, downgrade, and reinstall: old `prerm upgrade <new>`, new `preinst
  upgrade <old>`, unpack, old `postrm upgrade <new>`, conffile decisions, then
  `postinst configure <old>`;
- remove: `prerm remove`, `half-installed`, owned-file removal retaining
  conffiles, `postrm remove`, `config-files`;
- purge: the remove sequence when files are still installed, then `postrm
  purge`, conffile deletion, metadata removal, and removal of the status
  record;
- essential bootstrap materialization precedes all other lifecycle work, and
  each `Pre-Depends` barrier configures every pending package before the next
  unpack. A dependency cycle configures its whole group at one barrier.

Maintainer scripts are emitted only when the corresponding evidence proves the
script exists, so the program never plans a call to a script that is not there.

## Validation

Compilation returns either a complete program or exactly one typed diagnostic;
there is no partial program. It rejects, among others:

- a non-native backend or a lock generation other than exact closure lock v2;
- a maintainer-script policy that disagrees with the authorized host-root
  policy;
- an unsupported root feature or a non-quiescent database;
- missing, duplicate, extra, misidentified, or mismatched archives, including
  origin mismatches;
- duplicate installed identities, invalid identities, versions, paths, conffile
  or trigger metadata;
- installed state that contradicts the action, such as installing over an
  installed package, upgrading from a different recorded version, or acting on
  an unhealthy state;
- an ordering that drops, duplicates, reorders, or invents work relative to the
  authorized actions, a missing configure barrier, or a lifecycle that revisits
  an already configured package;
- an ownership conflict that neither `Replaces` nor the reviewed force policy
  resolves;
- a modeled final state that contradicts the authorized final closure, a
  package missing from it, or a closure entry that is neither installed nor
  authorized;
- any limit or arithmetic bound violation, including the compile work budget.

Validation is linear or hash-indexed under large bounds; there are no quadratic
scans over packages, conffiles, paths, or steps.

## Determinism and digests

The program is independent of allocation, hash iteration, and input map order:
installed packages, conffiles, scripts, trigger declarations, ownership
conflicts, and `Replaces` sets are normalized into one canonical order, and
artifacts follow the authorization's dense action order. Semantically identical
inputs produce byte-identical documents.

The canonical document is minified JSON in fixed field order. `digest_sha256`
is a domain-separated SHA-256 over the complete document with its own digest
field replaced by 64 ASCII zeros, so every other field, including the artifact
and step sub-digests, is bound. Changing any mutation- or security-relevant
input, such as the database generation, an application digest, a script digest,
a conffile digest, the environment policy, or the reviewed mutation policy,
changes the program digest.

Decoding is strict: bounded input, unknown fields, duplicate fields, missing
fields, non-canonical bytes, forward or oversized step dependencies, dense
sequence violations, artifact index violations, non-hexadecimal digests,
invalid identities, paths, or trigger names, and any digest mismatch fail
closed. `NativeTransactionProgramStore` publishes and rereads the document with
no-follow, atomic, fsynced writes so a later recovery reads exactly the bytes
that authorized the mutation.

## Engine binding

`transaction_engine.authorizeProgram` requires the compiled program for native
execution, rejects one supplied to the legacy backend, and verifies the schema,
the authorization binding, the mutation policy, the executor-policy digest, and
every artifact against the request the backend would run. It also accepts an
independently recorded expected program digest, which durable recovery evidence
will use to require the exact program that the interrupted attempt published.
`executeAuthorizedProgram` performs all of that before backend selection can
reach an executor.

`legacy_dpkg` remains the default backend and no native executor is registered,
so a correct program still cannot start a native transaction yet: selection
returns the typed unavailable result and never falls back.

## Not in v1

Diversions, statoverride records, and alternatives are preserved by the
database contract but are not yet expanded into program steps. Live filesystem
inspection, package-database writes, and script execution remain outside this
module by design.
