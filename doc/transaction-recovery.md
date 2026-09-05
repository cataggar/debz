# Transaction recovery

`executeTransaction` now requires an injected journal store and installed-state
reader. Before any dpkg mutation it writes a checksummed version-3 journal that
binds the plan digest, install-root identity, package archive digests, exact
command digests, executor policy, and optional system attempt identifier. Each
command is bracketed by atomic, durable journal updates.

States are `not_started`, `in_progress`, `dpkg_failed`, `interrupted`,
`verification_failed`, and `complete`. A normal execute never silently resumes
an existing interrupted transaction. Call `recoverTransaction` explicitly with
the same plan, root, and policy.

The standalone system workflow stores its journal and recovery intent in the
per-operation transaction directory. A root-scoped system-operation advisory
lock at `INSTALL_ROOT/var/lib/debz/system-operation.lock` serializes intent
inspection, publication, execution, and cleanup even when callers select
different state directories. It is distinct from the executor's
transaction/dpkg locks, so lock ordering cannot self-deadlock. Before
refreshing or planning another mutation, it checks the active intent at
`INSTALL_ROOT/var/lib/debz/recovery-request.json`; that intent points to the
selected state directory's immutable per-operation evidence. If mutation
began, any install request returns typed `recovery_required` with the retained lock/recovery paths
without network access or construction of another lock. The intent names the
attempt and operation-lock digest only; all paths are derived from the
root-owned operation lock's validated install/state roots and attempt identity.
The evidence directory is created exclusively and parent directories are
fsynced before intent publication. `debz recover` loads the canonical
transaction-plan-v3 and optional package lock from those derived paths and invokes
recovery without repository refresh, solver execution, or reconstruction from
post-failure dpkg state. A nonmatching request, action, request digest, policy
digest, state root, attempt, plan digest, or package-lock digest is rejected.
Failed recovery retains the same evidence. Successful recovery publishes
attempt-bound transaction-result-v3 provenance before clearing the active
intent. A failure proven to occur before journal creation removes both active
intents only after a successful no-journal probe; read, delete, and fsync errors
retain the recovery requirement.

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
