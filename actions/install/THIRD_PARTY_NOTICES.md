# Third-party notices for `actions/install`

The checked-in JavaScript bundle includes the pinned dependencies and
transitive versions recorded in `package-lock.json`. Complete license texts
emitted by the bundler are committed as `dist/licenses.txt`.

Direct runtime dependency:

| Package | License |
| --- | --- |
| `@actions/core` | MIT |

The install action invokes the checked-in `actions/setup` and
`actions/download` bundles from the same immutable repository revision; their
dependency notices remain in those action directories.

The action itself is licensed under the repository's Apache-2.0 license.
