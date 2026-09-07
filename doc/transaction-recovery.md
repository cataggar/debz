# Transaction recovery

`executeTransaction` now requires an injected journal store and installed-state
reader. Before any dpkg mutation it writes a checksummed version-1 journal that
binds the plan digest, install-root identity, package archive digests, exact
command digests, and executor policy. Each command is bracketed by atomic,
durable journal updates.

States are `not_started`, `in_progress`, `dpkg_failed`, `interrupted`,
`verification_failed`, and `complete`. A normal execute never silently resumes
an existing interrupted transaction. Call `recoverTransaction` explicitly with
the same plan, root, and policy.

Recovery acquires the same bounded locks, validates journal integrity and
identity, then runs only:

1. `dpkg --audit`
2. `dpkg --configure --pending`
3. `dpkg --triggers-only --pending`

No broad force flags are used. Recovery is safe to repeat. A complete journal
is atomically archived; failure journals remain active evidence.

Completion requires parsing the caller-bound dpkg status database. Every
package must avoid repair/intermediate states. Planned installs/upgrades must
match package, architecture, and version exactly; planned removals must not be
installed. Unrelated healthy installed packages are allowed by the documented
default policy because a transaction plan describes its changed identities,
not a complete root manifest. The dpkg database lock is reacquired under the
bounded lock policy before this final query, so completion is never decided
from a concurrently changing status database.

Exact locks are stricter unless the caller selects the policy-bound
`locked_packages` mode. Full-closure verification rejects every installed
identity absent from the lock. Operation-scoped verification instead checks
every locked package and its plan/journal origin evidence exactly while
allowing unrelated healthy identities; the distinct executor policy digest
prevents a journal from being replayed under the other interpretation.

`SystemJournalStore` provides fsync-and-rename publication in an explicit
directory and refuses symlinked path components. `SystemStatusFileReader`
securely walks and reads only the explicit install root.
Process, filesystem, locks, journal, status, cancellation, and crash points are
all injectable for host-isolated testing.

## Root operation coordination

The transaction journal remains the command-level recovery authority, but it is
no longer the only durable evidence. Every mutating product operation and every
repository bootstrap first reserves the shared root attempt described in
[root-scoped operation coordination](root-operation.md). The root mutation lock
is rank 0 of the total lock order and is taken before the journal, the package
cache, and the executor's target locks; it is held through provenance
publication and the clearing of the active intent.

The durable record classifies an interrupted operation. `reserved` and
`preflight` prove no mutation and are cleared automatically. `mutation_pending`
means control reached the command-oriented executor and is resolved only by an
explicit witness derived from the executor's own transaction state. A command
count alone is never that witness: command provenance is appended only after a
command has completed, so a first command that timed out, hit the operation
deadline, lost a lock, or failed to spawn reports zero commands after `dpkg`
may already have mutated the root, and a plan the executor drove to `complete`
can report none either. Only zero commands together with a `not_started`
transaction state proves nothing started; every other state records mutation
evidence. From `mutating` onwards a second mutation is refused until it is
resolved — by an explicit recovery for package transactions, or by a rerun of
the very same repository bootstrap request, which adopts its own attempt
instead of opening a new mutation intent — and provenance is published before
the active intent is cleared.

A completion that was interrupted after the terminal `completed` record but
before its provenance was published is the one case the journal cannot resolve.
That transaction finished and its journal was archived, so a rerun asks the
archive about a plan it was never written for. `debz recover` therefore
discharges the obligation directly, without running the engine again: it
verifies whatever detailed transaction provenance survived, publishes the
root-operation completion statement described in
[root-scoped operation coordination](root-operation.md), binds the record to
it, and only then clears the intent. Any mismatch, corruption, or I/O failure
around that evidence leaves the record exactly as it was, with a diagnostic
naming the document to inspect.
