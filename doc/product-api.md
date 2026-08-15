# Stable product API and CLI contract

The versioned façade is `debz.product_api`. Callers construct a
`product_api.Request`, provide all `CommonOptions`, and call
`debz.executeProductRequest` with an injected `ProductBackend`. The backend is
the composition boundary for authenticated refresh, parsed dpkg state,
deterministic planning, verified acquisition, payload validation, transaction
execution/recovery, locks, and provenance. This keeps CLI parsing out of
embedders and avoids duplicating those modules.

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

Inputs are explicit: `--source`, `--config`, `--keyring`, `--default-release`,
`--repository-policy`, `--lock-input`, `--lock-output`, `--offline`,
`--proxy`, `--credential-reference`, `--cache-only`, `--recommends`,
`--allow-downgrade`, `--deadline-ms`,
`--lock-wait-ms`, `--noninteractive`, `--conffile`, and typed `--force`
policies. Paths must be absolute and traversal-free. No host APT configuration,
keyring, proxy, credential, or environment is inherited.

Every mutating command requires `--assume-yes`. Noninteractive transaction
commands additionally require `--conffile keep-existing` or
`--conffile use-package-version`. `plan` and `download` are non-executing.

The standalone binary deliberately fails with exit 3 when no operation backend
has been linked/configured; this is an explicit failure, not simulated success.
Applications normally supply the façade backend while composing the existing
debz modules for their repository and transaction environment.

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
