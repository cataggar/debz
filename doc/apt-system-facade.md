# Apt-shaped system facade contracts

`debz.apt_system_api` is a separate versioned orchestration contract for a
future deliberately limited `debz apt` interface. It preserves product API v1
unchanged. This change defines data, validation, durable state, and evidence
boundaries only; it does not add CLI parsing, dependency-solver behavior,
mount namespaces, live-root views, or production orchestration.

The interface is **apt-shaped, not apt-compatible**. It promises no apt output,
wording, exit-code convention, option aliases, configuration discovery, or
dependency-resolution edge behavior. There is no `apt-get` alias and no
passthrough to apt or dpkg. Unsupported syntax must become a typed usage
outcome before repository, root, or package mutation.

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

Null or omitted proxy and credential fields mean disabled. They never mean
"read apt.conf", "inspect the environment", or "discover credentials".
Likewise, the loader never consults `/etc/apt`, ambient keyrings, GnuPG
configuration, dpkg configuration, or process environment settings.

`system_profile.load` takes an injected filesystem interface. The profile and
every source, config, keyring, and credential file are bounded and must be a
canonical absolute non-root path, a regular file opened without following any
symbolic-link component or leaf, owned by uid 0, and not group- or
world-writable. Metadata must be modeled rather than assumed. The production
Linux implementation obtains ownership and mode from the opened descriptor;
tests inject metadata and do not require root.

Profiles reject unknown JSON fields, duplicate repositories, keyrings or
foreign architectures, credential-bearing proxy URLs, invalid architectures,
unsafe paths, excessive bytes, and excessive object counts. The loaded profile
records SHA-256 of the exact reviewed profile bytes for later request/result
binding.

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

Every result binds the canonical request digest. Once a profile is loaded it
also binds the profile path and exact-byte digest. Successful package mutation
is impossible to represent without all of:

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
operation record. It binds attempt and generation, operation, request, profile,
exact lock, transaction result, root-operation completion, mutation evidence,
phase, outcome, timestamp, and diagnostic. Its store reads without following a
symlink and publishes a mode-0600 staged file with file and directory sync
around atomic rename.

The state cannot call a package mutation successful or recovered without the
same lock, transaction, and root-completion evidence required by the result.
Once mutation has started, failure remains distinguishable from a
pre-mutation failure and the `recovery_required` phase cannot be represented as
safe abandonment.
