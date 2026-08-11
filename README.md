# rootmygalaxy-device-porter

Automation for porting the Root My Galaxy exploit payload to a new Samsung
firmware, following `docs/PORTING.md` in the
[Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads)
repository. The CI workflow runs the **whole mechanical port** and produces a
downloadable, testable artifact bundle — no manual header editing required to
get to a first on-device test.

## What "the whole port" means here

The CI does, in order:

1. **Firmware** — resolves the exact four-part version via `samloader`
   (or a direct URL) and downloads it.
2. **Kernel** — extracts `boot.img.lz4` from the AP tar, parses the Android
   boot header v4, and slices out the raw kernel Image.
3. **Identity** — reads `ro.build.fingerprint` / `ro.build.display.id` from
   `meta-data/fota.zip` inside the firmware zip (`rmg-port extract-fota`).
4. **BTF** — extracts the validated raw BTF blob and dumps struct sizes and
   member byte offsets with a **pure-Python BTF parser** (`rmg-port btf-struct`),
   so the pipeline no longer depends on a working `bpftool` on the runner.
5. **Recovery** — `vmlinux-to-elf` + `llvm-nm`, a `worker_thread` objdump, and
   the 32-row P0 fingerprint generated from the exact raw kernel.
6. **Derivation** — `rmg-port gen-target-h` rewrites the scaffolded `target.h`
   so every derivable constant comes from **this firmware**, not the source
   target:
   - `BUILD_FINGERPRINT` ← fota.zip `ro.build.fingerprint`
   - symbol offsets (`INIT_TASK_OFF`, `ASHMEM_*`, `CONFIGFS_*`,
     `KMALLOC_CACHES_OFF`, ...) ← `nm[symbol] − ELF base`
   - composite offsets (`ASHMEM_MISC_FOPS_OFF`, `SELINUX_ENFORCING_OFF`) ←
     nm symbol + BTF member
   - struct offsets (`FAKE_TASK_*`, `FOPS_*`, `WORK_*`, `STRUCT_PAGE_*`,
     workqueue/pool, configfs buffer) ← raw BTF
   - `SLIDE_TRACEFS_WORKER_CALLER_OFF` ← next instruction after the single
     `bl schedule` in `worker_thread` (only when unambiguous)
   - everything else (physical load addresses, trace event ID, pselect shift,
     fake-task layout) is kept from the scaffold and **explicitly flagged** in
     `src/targets/<profile>/port-report.md`.
7. **Build** — `make TARGET=<profile> release` with the NDK, publishing
   `artifacts/<profile>/cve-2026-43499-app.so` (size-gated).
8. **KernelSU** — `reuse` an existing `ksud-*` artifact (same KMI), or
   `kernelsu_build=ddk` to build the module in the
   `ghcr.io/ylarod/ddk-min` container, run `check_symbol` + the manual
   relocation audit against the recovered `vmlinux.elf`, embed the KO, and
   rebuild `ksud` with the NDK toolchain.
9. **Feed + gates** — updates `support/targets-v3.json`, then runs
   `validate-feed`, `validate-port`, and `validate-analysis` (symbol-vs-nm and
   BTF-vs-header cross-checks).
10. **Artifacts** — uploads the port bundle (kernel, nm, ELF, BTF, struct
    offsets, derived header, `.so`, feed) to the Actions run so you can test
    without waiting for a PR merge.
11. **PR** — opens the payload PR when `dry_run=false` and
    `PAYLOADS_PR_TOKEN` is set.

## Dispatch

Run the **Device Port PR** workflow with inputs:

| Input | Meaning |
| --- | --- |
| `profile` | `src/targets/<profile>` dir, e.g. `a36xq-A366WVLS3AYG1` |
| `model` / `region` | `Build.MODEL` + Samsung CSC used by samloader |
| `version` | four-part version, or `latest` to resolve via samloader |
| `source_target` | existing target used as the header scaffold |
| `kernel_version` | leading `uname -r` for the feed, e.g. `6.6.46` |
| `display_name` | feed display name |
| `kernelsu_build` | `reuse` (default), `ddk`, or `none` |
| `kernelsu_artifact` | existing ksud path for `reuse`, e.g. `kernelsu/ksud-s25u-kdp` |
| `kernelsu_ddk_image` | DDK container for `ddk`, e.g. `ghcr.io/ylarod/ddk-min:android14-6.1-20260313` |
| `kernelsu_kmi_asset` | embedded KO asset name for `ddk`, e.g. `android14-6.1_kernelsu.ko` |
| `kernelsu_release` | exact target release for the DDK vermagic; auto-detected from the kernel banner when empty |
| `dry_run` | `true` = build + validate, no PR |

## What is NOT derivable offline

These constants are scaffolded from `source_target` and must be verified on the
target before the port is trusted (they are listed in `port-report.md` and in
the PR body):

- `P0_PAGE_OFFSET`, `P0_PHYS_OFFSET`, `P0_KERNEL_PHYS_LOAD` (from `sboot.bin`
  disassembly)
- `SLIDE_TRACEFS_EVENT_ID` (runtime tracefs or ftrace enum analysis)
- `SLIDE_PSELECT_WORD_SHIFT` (pselect6 stack layout)
- fake-task / waiter layout offsets (`LOCK_OFF`, `FAKE_WAITER_*`, ...)

A green CI run proves the pipeline is mechanically coherent; hardware
execution is still the final validation step, exactly as the upstream docs
treat it.

## Local checks

```sh
python -m pip install -e .[lz4]
PYTHONPATH=src python tests/verify_derivation.py   # btf-struct / extract-fota / gen-target-h
PYTHONPATH=src python tests/verify_pipeline.py     # scaffold -> derive -> feed -> gates
```
