# Offline Checks

The porter enforces the offline checks that can be validated from files in CI.

Always enforced:

- firmware AP build matches the target profile name;
- `target.h` `BUILD_FINGERPRINT` contains the AP build;
- required target macros and accepted legacy aliases exist;
- `target.h` references `targets/<profile>/p0_fingerprint.h`;
- release payload exists and is within the fixed release-size limit;
- P0 fingerprint contains all 32 slides from `0x000000` through `0x1f0000`;
- each P0 row contains 8 qwords;
- support feed has exactly one expected `payloadId`;
- support feed includes the requested three-part kernel version;
- support feed artifact sizes match local files;
- KernelSU late-load artifact path exists when supplied.

Enforced when supplied:

- raw kernel file exists and has a plausible size;
- raw BTF file exists and starts with the validated little-endian BTF header;
- standalone KernelSU `.ko` artifact exists.

Not proven by offline CI alone:

- every `target.h` offset is correct unless a separate vmlinux/BTF symbol
  derivation step produces machine-checkable expected values;
- KernelSU `check_symbol` or manual-relocation audit unless the exact `.ko`,
  recovered `vmlinux`, and symbol-version data are provided;
- exploit success or KernelSU activation on hardware.

The workflow should fail closed before opening a PR when offline identity or
artifact checks fail.
