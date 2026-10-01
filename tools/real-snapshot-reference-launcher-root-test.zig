//! Root-only reference launcher proof. `zig build test-real-snapshot-reference-launcher-root`
//! runs this binary through `sudo -n`; it fails with `CapabilityProbeRequiresRoot`,
//! never skips, without UID 0. Importing the launcher also reruns its
//! unprivileged tests as root, including the UID/GID 65534 refusal.
const launcher = @import("real-snapshot-reference-launcher.zig");

test "reference capability transition clears ambient and high bounding privileges as root" {
    try launcher.capabilityTransitionProbe();
}
