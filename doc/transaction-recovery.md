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
