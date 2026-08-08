# S25 Ultra Baseline Action Inputs

The latest upstream-supported S25-series payload is:

```text
payloadId: galaxy-s25-series-2026-06-07
source target: pa3q-S938NKSUACZF1
displayName: Galaxy S25 series | Kernel 6.6.98
kernelVersions: 6.6.98
exploit artifact: artifacts/pa3q-S938NKSUACZF1/cve-2026-43499-app.so
exploit size: 104128
KernelSU artifact: kernelsu/ksud-s25u-kdp
KernelSU size: 6407096
standalone KO: kernelsu/android15-6.6_kernelsu-s25u-kdp.ko
standalone KO size: 3543168
probe offset: 0x1f0000
```

For a workflow smoke test that should reproduce the same shape as the current
supported S25 Ultra target, use:

```text
payloads_repo: rushiranpise/Root-My-Galaxy-Payloads
profile: pa3q-S938NKSUACZF1
model: SM-S938N
region: KOO
version: latest
source_target: pa3q-S938NKSUACZF1
replace_existing_target: true
probe_offset: 0x1f0000
kernel_version: 6.6.98
kernel_release: 6.6.98
display_name: Galaxy S25 Ultra | Kernel 6.6.98
kernelsu_artifact: kernelsu/ksud-s25u-kdp
dry_run: true
```

Notes:

- If `profile` already exists in the payload repo, `scaffold-target` will stop.
  That is useful for real ports, but for a pure S25 smoke test use a scratch
  profile name or delete the generated branch after testing.
- Use `firmware_url` when you already have a direct firmware ZIP URL. Leave it
  empty to make the action call `samloader`. Use `version: latest` to make the
  action resolve the `Latest Stable Version` with `samloader check-update`.
- The current support-feed entry is shared across S25/S25+/S25 Edge/S25 Ultra
  regional models. A real support PR should preserve that shared payload shape
  unless the new firmware truly needs a separate artifact.
