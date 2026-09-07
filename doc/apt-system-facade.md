# Apt-shaped system facade contracts

`debz.apt_system_api` is a separate versioned orchestration contract for a
future deliberately limited `debz apt` interface. `debz.apt_system_cli` now
defines its pure parsing, help, rendering, and confirmation-decision contract.
It preserves product API v1 and the existing root CLI unchanged. The module is
not yet wired into `main.zig` and does not execute dependency-solver behavior,
mount namespaces, live-root views, or production orchestration.

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
ask later integration for TTY confirmation; a JSON request instead requires a
typed `confirmation_required` result and can never request a prompt.

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
machine interface.

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
- the verified transaction-result path, schema version, and digest; and
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
