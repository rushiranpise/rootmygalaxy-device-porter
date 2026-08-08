# Root My Galaxy Device Porter

Automation helper for adding a new device profile to
`Root-My-Galaxy-Payloads`.

This repo does not try to invent kernel offsets. It automates the repeatable
parts around a port:

- record the exact Samsung firmware identity;
- extract and hash boot/kernel images;
- extract a raw BTF blob when present;
- generate the P0 fingerprint header from the raw kernel image;
- create a target skeleton in the payload repo;
- validate `support/targets-v3.json` artifact paths and sizes;
- produce a PR checklist showing what still needs human/device validation.

## Why this exists

Adding support is not only "download ROM, test, PR". The payload repo needs an
exact firmware profile:

1. exact model, region, AP/CSC/CP/build fingerprint, and kernel release;
2. target-specific `src/targets/<profile>/target.h`;
3. target-specific `p0_fingerprint.h`;
4. a release payload in `artifacts/<profile>/cve-2026-43499-app.so`;
5. a matching KernelSU late-load artifact;
6. a `support/targets-v3.json` entry with model and kernel-version matching;
7. docs proving where the values came from and what was tested.

This tool makes the mechanical pieces boring, and keeps the dangerous or
device-specific decisions visible.

## Install

```powershell
cd C:\Users\rushi\OneDrive\Documents\ext\rootmygalaxy\rootmygalaxy-device-porter
python -m pip install -e .
```

Optional external tools used by specific steps:

- `samloader-rs` or `samloader` for Samsung firmware downloads;
- `lz4` Python package for `.lz4` image extraction;
- `vmlinux-to-elf`, `llvm-nm`, `llvm-objdump`, `bpftool`, and `pahole` for
  symbol/BTF work;
- Android NDK r29 for payload builds;
- Docker or a prepared kernel tree for KernelSU module builds.

## Quick Start

Create a work plan:

```powershell
rmg-port init --profile a36xq-A366WVLS3AYG1 --model SM-A366W --region OYV --workdir .work\a36
```

Extract a kernel from Samsung firmware files:

```powershell
rmg-port extract-kernel --firmware-zip .work\a36\A366WVLS3AYG1_OYV.zip --workdir .work\a36
```

Generate the P0 fingerprint header:

```powershell
rmg-port gen-p0 --kernel .work\a36\kernel --probe-offset 0x1f0000 --out .work\a36\p0_fingerprint.h
```

Create the target directory skeleton in the payload repo:

```powershell
rmg-port scaffold-target --payloads-repo ..\Root-My-Galaxy-Payloads --profile a36xq-A366WVLS3AYG1 --source-target a36xq-A366WVLS3AYG1 --p0-header .work\a36\p0_fingerprint.h
```

Validate the support feed:

```powershell
rmg-port validate-feed --payloads-repo ..\Root-My-Galaxy-Payloads
```

Print the remaining PR checklist:

```powershell
rmg-port checklist --payloads-repo ..\Root-My-Galaxy-Payloads --profile a36xq-A366WVLS3AYG1
```

## GitHub Actions

This repo includes `.github/workflows/device-port-pr.yml`, a manual pipeline
that can download firmware, generate files, build the release payload, update
the support feed, and open a PR against `Root-My-Galaxy-Payloads`.

See [`docs/GITHUB_ACTIONS_PIPELINE.md`](docs/GITHUB_ACTIONS_PIPELINE.md).
The default PR target is `rushiranpise/Root-My-Galaxy-Payloads`; S25 Ultra
baseline inputs are in
[`docs/S25_ULTRA_ACTION_INPUTS.md`](docs/S25_ULTRA_ACTION_INPUTS.md).

## Current Boundary

The tool intentionally does not:

- derive all exploit offsets automatically;
- copy offsets between devices as if they are compatible;
- claim a device is supported before hardware validation;
- create or push GitHub PRs until the local checks pass.

Those are the exact places where a bad automation would make the process look
easy while producing broken or unsafe payloads.
