# GitHub Actions Pipeline

The workflow in `.github/workflows/device-port-pr.yml` is designed to run from
this porter repo and open a PR against `Root-My-Galaxy-Payloads`.
By default it targets `rushiranpise/Root-My-Galaxy-Payloads`.

## What It Can Automate

- checkout the porter repo and payload repo;
- download firmware from a direct URL or with `samloader-rs`;
- extract `boot.img`, the raw kernel, and BTF when present;
- generate `p0_fingerprint.h`;
- create `src/targets/<profile>` from an existing target scaffold;
- build the release payload with `make TARGET=<profile> release`;
- copy the release `.so` into `artifacts/<profile>/`;
- update `support/targets-v3.json`;
- create a PR branch and open a PR.

## Required Secret

Create a repository secret in the porter repo:

```text
PAYLOADS_PR_TOKEN
```

It needs permission to push branches and open PRs on the payload repo.

For the current S25 Ultra baseline values, see
[`S25_ULTRA_ACTION_INPUTS.md`](S25_ULTRA_ACTION_INPUTS.md).

## Manual Gate

The generated PR is not automatically merge-ready. Someone still has to review:

- copied `target.h` values and replace them with exact target-derived offsets;
- tracefs/pselect/worker-caller values;
- KernelSU module compatibility and `ksud` artifact;
- hardware test results.

This is deliberate. The action removes the repetitive work without hiding the
parts that can brick the port.
