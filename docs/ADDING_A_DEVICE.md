# Adding a Device

Use this as the automation target for a new Root My Galaxy device port.

## Mechanical Steps

1. Check Samsung FUS for the exact model/region/version.
2. Download the exact firmware package.
3. Extract `boot.img.lz4` from the AP archive.
4. Decompress `boot.img`, then extract the raw ARM64 kernel using the boot
   header `kernel_size`.
5. Hash the firmware, boot image, and raw kernel.
6. Recover `vmlinux.elf` with `vmlinux-to-elf`.
7. Extract BTF from the raw kernel when available.
8. Dump symbols and BTF layouts.
9. Fill `target.h` from the target kernel only.
10. Generate `p0_fingerprint.h` from the target raw kernel.
11. Build `make TARGET=<profile> release`.
12. Copy the app payload to `artifacts/<profile>/cve-2026-43499-app.so`.
13. Build and audit the matching KernelSU artifacts.
14. Add or update one `support/targets-v3.json` payload entry.
15. Add docs with provenance and validation status.

## Values That Must Be Derived Per Firmware

- `BUILD_FINGERPRINT`
- `KIMAGE_TEXT_BASE`
- physical load constants
- all symbol offsets in `target.h`
- all BTF structure sizes and member offsets
- tracefs event ID and worker caller offset
- pselect word shift
- P0 fingerprint table
- KernelSU vermagic and symbol compatibility

## Values That Can Usually Be Copied First, Then Reviewed

- app timing constants from a nearby tested target;
- scratch layout offsets used by the shared exploit;
- generic direct-map ranges for the same kernel family.

Copied values are placeholders until a real device test proves them.
