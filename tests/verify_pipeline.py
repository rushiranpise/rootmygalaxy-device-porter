"""End-to-end pipeline regression for the Device Port PR flow.

Run with:  python tests/verify_pipeline.py
Simulates the CI steps on a throwaway payloads repo: scaffold-target,
gen-target-h, add-feed-entry, validate-feed, validate-port,
validate-analysis, checklist.
"""
from __future__ import annotations

import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PAYLOADS = REPO.parent / "Root-My-Galaxy-Payloads"
TEMPLATE = PAYLOADS / "src" / "targets" / "essi-S721NKSSCDZF3" / "target.h"
CLI = [sys.executable, "-m", "rmg_porter.cli"]

PROFILE = "essi-A111B"
AP_BUILD = "A111B"
FINGERPRINT = "samsung/r12sksx/essi:16/BP4A.251205.006/A111B:user/release-keys"
KIMAGE_TEXT_BASE = 0xFFFFFFC008000000
KERNEL_VERSION = "6.1.157"
FOUR_PART = f"{AP_BUILD}/A111C/A111B/A111B"


def build_nm() -> str:
    text = TEMPLATE.read_text(encoding="utf-8")
    lines = []
    for macro, sym in [
        ("ASHMEM_FOPS_OFF", "ashmem_fops"),
        ("ASHMEM_IOCTL_OFF", "ashmem_ioctl"),
        ("ASHMEM_COMPAT_IOCTL_OFF", "compat_ashmem_ioctl"),
        ("ASHMEM_MMAP_OFF", "ashmem_mmap"),
        ("ASHMEM_OPEN_OFF", "ashmem_open"),
        ("ASHMEM_RELEASE_OFF", "ashmem_release"),
        ("ASHMEM_SHOW_FDINFO_OFF", "ashmem_show_fdinfo"),
        ("CONFIGFS_READ_ITER_OFF", "configfs_read_iter"),
        ("CONFIGFS_BIN_WRITE_ITER_OFF", "configfs_bin_write_iter"),
        ("COPY_SPLICE_READ_OFF", "generic_file_splice_read"),
        ("NOOP_LLSEEK_OFF", "noop_llseek"),
        ("INIT_TASK_OFF", "init_task"),
        ("ROOT_TASK_GROUP_OFF", "root_task_group"),
        ("KMALLOC_CACHES_OFF", "kmalloc_caches"),
        ("ANON_PIPE_BUF_OPS_OFF", "anon_pipe_buf_ops"),
        ("CALL_USERMODEHELPER_EXEC_WORK_OFF", "call_usermodehelper_exec_work"),
        ("SYSTEM_UNBOUND_WQ_OFF", "system_unbound_wq"),
        ("SLIDE_NFULNL_LOGGER_OBJECT_OFF", "nfulnl_logger"),
        ("SLIDE_SYSCTL_BOOTID_OFF", "sysctl_bootid"),
        ("ASHMEM_MISC_FOPS_OFF", "ashmem_misc"),
        ("SELINUX_ENFORCING_OFF", "selinux_state"),
    ]:
        m = re.search(rf"#define\s+{macro}\s+0x([0-9a-fA-F]+)", text)
        assert m, f"template missing {macro}"
        member_offset = {"ASHMEM_MISC_FOPS_OFF": 0x10, "SELINUX_ENFORCING_OFF": 0x04}.get(macro, 0)
        addr = KIMAGE_TEXT_BASE + int(m.group(1), 16) - member_offset
        lines.append(f"{addr:016x} T {sym}")
    for i in range(1200):
        lines.append(f"{KIMAGE_TEXT_BASE + 0x100000 + i * 0x10:016x} t foo_symbol_{i}")
    return "\n".join(lines) + "\n"


def build_btf() -> bytes:
    structs = {
        "task_struct": [("usage", 0x40), ("prio", 0x84), ("normal_prio", 0x8C), ("sched_task_group", 0x348),
                        ("pi_lock", 0x924), ("pi_waiters", 0x938), ("pi_top_task", 0x948), ("pi_blocked_on", 0x950)],
        "file_operations": [("owner", 0x00), ("llseek", 0x08), ("read", 0x10), ("write", 0x18),
                            ("read_iter", 0x20), ("write_iter", 0x28), ("unlocked_ioctl", 0x50),
                            ("compat_ioctl", 0x58), ("mmap", 0x60), ("open", 0x70), ("release", 0x80),
                            ("splice_read", 0xC8), ("show_fdinfo", 0xE0)],
        "page": [("flags", 0x00), ("compound_head", 0x08), ("slab_cache", 0x18), ("page_type", 0x30)],
        "work_struct": [("data", 0x00), ("entry", 0x08), ("func", 0x18)],
        "miscdevice": [("minor", 0x00), ("name", 0x08), ("fops", 0x10)],
        "selinux_state": [("disabled", 0x00), ("enforcing", 0x04)],
    }
    sizes = {"task_struct": 0x22C0, "file_operations": 0x110, "page": 0x40, "work_struct": 0x20,
             "miscdevice": 0x18, "selinux_state": 0x10}
    strings = [b"\x00"]
    seen: dict[str, int] = {}

    def intern(name: str) -> int:
        if not name:
            return 0
        if name in seen:
            return seen[name]
        off = sum(len(s) for s in strings)
        strings.append(name.encode() + b"\x00")
        seen[name] = off
        return off

    type_bytes = bytearray()
    for sname, members in structs.items():
        type_bytes += struct.pack("<III", intern(sname), (4 << 24) | len(members), sizes[sname])
        for mname, off in members:
            type_bytes += struct.pack("<III", intern(mname), 0, off << 3)
    str_bytes = b"".join(strings)
    header = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(type_bytes), len(type_bytes), len(str_bytes))
    return header + bytes(type_bytes) + str_bytes


def run(args: list[str], cwd: Path) -> str:
    proc = subprocess.run(CLI + args, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"cli {' '.join(args)} failed (rc {proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout


def main() -> None:
    if not TEMPLATE.exists():
        raise SystemExit(f"template target.h not found: {TEMPLATE}")
    work = Path(tempfile.mkdtemp(prefix="rmg-pipeline-"))
    sys.path.insert(0, str(REPO / "src"))
    try:
        # fake payloads repo: seed the source target and kernelsu artifacts
        payloads = work / "payloads"
        (payloads / "src" / "targets").mkdir(parents=True)
        (payloads / "artifacts").mkdir(parents=True)
        (payloads / "kernelsu").mkdir(parents=True)
        (payloads / "support").mkdir(parents=True)
        (payloads / "docs").mkdir(parents=True)
        shutil.copytree(PAYLOADS / "src" / "targets" / "essi-S721NKSSCDZF3",
                        payloads / "src" / "targets" / "essi-S721NKSSCDZF3")
        shutil.copy(PAYLOADS / "support" / "targets-v3.json", payloads / "support" / "targets-v3.json")
        shutil.copy(PAYLOADS / "kernelsu" / "ksud-s25u-kdp", payloads / "kernelsu" / "ksud-s25u-kdp")

        w = work / "work"
        (w / PROFILE).mkdir(parents=True)
        nm_path = w / PROFILE / "vmlinux.nm"
        nm_path.write_text(build_nm(), encoding="utf-8")
        btf_path = w / PROFILE / "vmlinux.btf"
        btf_path.write_bytes(build_btf())
        so_path = w / PROFILE / "struct-offsets.json"
        run(["btf-struct", "--btf", str(btf_path), "--out", str(so_path), "--structs", "all"], cwd=REPO)

        # fota props with the new AP build so BUILD_FINGERPRINT validates
        fota = work / "fota.zip"
        with zipfile.ZipFile(fota, "w") as zf:
            zf.writestr("system/build.prop", f"ro.build.fingerprint={FINGERPRINT}\nro.build.display.id=BP4A.251205.006.{AP_BUILD}\n")
        firmware = work / "firmware.zip"
        with zipfile.ZipFile(firmware, "w") as zf:
            zf.write(fota, "meta-data/fota.zip")
        props_path = w / PROFILE / "fota-props.json"
        run(["extract-fota", "--firmware-zip", str(firmware), "--out", str(props_path)], cwd=REPO)

        (w / PROFILE / "resolved-version.txt").write_text(FOUR_PART + "\n", encoding="utf-8")
        (w / PROFILE / "kernel-release.txt").write_text("6.1.157-android14-11\n", encoding="utf-8")
        (w / PROFILE / "kernel").write_bytes(b"\x00" * (20 * 1024 * 1024))  # dummy raw kernel

        # 1. scaffold (skip header) -> 2. derive target.h
        run(["scaffold-target", "--payloads-repo", str(payloads), "--profile", PROFILE,
             "--source-target", "essi-S721NKSSCDZF3",
             "--p0-header", str(PAYLOADS / "src" / "targets" / "essi-S721NKSSCDZF3" / "p0_fingerprint.h"),
             "--skip-target-header"], cwd=REPO)
        run(["gen-target-h", "--target-dir", str(payloads / "src" / "targets" / PROFILE),
             "--template", str(TEMPLATE), "--profile", PROFILE,
             "--fota-props", str(props_path), "--vmlinux-nm", str(nm_path),
             "--elf-base", hex(KIMAGE_TEXT_BASE), "--struct-offsets", str(so_path)], cwd=REPO)
        original_target_h = (payloads / "src" / "targets" / PROFILE / "target.h").read_bytes()
        header = original_target_h.decode("utf-8")
        assert FINGERPRINT in header
        assert f"targets/{PROFILE}/p0_fingerprint.h" in header
        report = (payloads / "src" / "targets" / PROFILE / "port-report.md").read_text(encoding="utf-8")
        derived = sum(1 for l in report.splitlines() if l.startswith("- [DERIVED]"))
        kept = sum(1 for l in report.splitlines() if "already correct in template; kept as-is" in l)
        assert derived + kept >= 50, f"only {derived} derived + {kept} value-matched entries"
        print(f"PASS scaffold+derive: target.h written with {derived} derived + {kept} value-matched macros")

        # 3. fake artifacts + feed entry + validation gates
        (payloads / "artifacts" / PROFILE).mkdir(parents=True)
        (payloads / "artifacts" / PROFILE / "cve-2026-43499-app.so").write_bytes(b"\x00" * 104128)
        run(["add-feed-entry", "--payloads-repo", str(payloads), "--profile", PROFILE,
             "--display-name", "Galaxy Test | Kernel 6.1.157",
             "--model", "SM-S721N", "--kernel-version", KERNEL_VERSION,
             "--exploit-path", str(payloads / "artifacts" / PROFILE / "cve-2026-43499-app.so"),
             "--kernelsu-path", str(payloads / "kernelsu" / "ksud-s25u-kdp")], cwd=REPO)
        # add-feed-entry must be idempotent: an identical update leaves the feed byte-identical
        feed_before = (payloads / "support" / "targets-v3.json").read_bytes()
        run(["add-feed-entry", "--payloads-repo", str(payloads), "--profile", PROFILE,
             "--display-name", "Galaxy Test | Kernel 6.1.157",
             "--model", "SM-S721N", "--kernel-version", KERNEL_VERSION,
             "--exploit-path", str(payloads / "artifacts" / PROFILE / "cve-2026-43499-app.so"),
             "--kernelsu-path", str(payloads / "kernelsu" / "ksud-s25u-kdp")], cwd=REPO)
        assert (payloads / "support" / "targets-v3.json").read_bytes() == feed_before
        print("PASS add-feed-entry idempotent: repeated identical update leaves the feed byte-identical")
        # replace path: updating a middle entry (not the last) must keep valid JSON
        # and preserve the trailing comma of the replaced span
        run(["add-feed-entry", "--payloads-repo", str(payloads), "--profile", PROFILE,
             "--payload-id", "galaxy-s25-series-2026-06-07",
             "--display-name", "Renamed S25 | Kernel 6.6.98",
             "--model", "SM-S938N", "--kernel-version", "6.6.98",
             "--exploit-path", str(payloads / "artifacts" / PROFILE / "cve-2026-43499-app.so"),
             "--kernelsu-path", str(payloads / "kernelsu" / "ksud-s25u-kdp")], cwd=REPO)
        feed_data = json.loads((payloads / "support" / "targets-v3.json").read_text(encoding="utf-8"))
        s25 = [p for p in feed_data["payloads"] if p["payloadId"] == "galaxy-s25-series-2026-06-07"]
        assert len(s25) == 1 and s25[0]["displayName"] == "Renamed S25 | Kernel 6.6.98", s25
        print("PASS add-feed-entry replace: middle entry updated in place, feed stays valid JSON")
        run(["validate-feed", "--payloads-repo", str(payloads)], cwd=REPO)
        run(["validate-port", "--payloads-repo", str(payloads), "--profile", PROFILE,
             "--version", FOUR_PART, "--kernel-version", KERNEL_VERSION,
             "--kernel-release", "6.1.157-android14-11",
             "--kernel", str(w / PROFILE / "kernel"),
             "--btf", str(btf_path),
             "--kernelsu-path", str(payloads / "kernelsu" / "ksud-s25u-kdp"),
             "--release-size-max", "200000"], cwd=REPO)
        # a run pointing at a missing kernel must fail the gate
        proc = subprocess.run(CLI + ["validate-port", "--payloads-repo", str(payloads), "--profile", PROFILE,
                                     "--version", FOUR_PART, "--kernel-version", KERNEL_VERSION,
                                     "--kernel", str(work / "nope-kernel"),
                                     "--kernelsu-path", str(payloads / "kernelsu" / "ksud-s25u-kdp"),
                                     "--release-size-max", "200000"],
                              cwd=REPO, capture_output=True, text=True)
        assert proc.returncode != 0 and "kernel file not found" in proc.stdout + proc.stderr
        print("PASS validate-port: green with real inputs, correctly fails on a missing kernel file")

        # legacy (pre-rename) headers name two slide macros differently; the gate
        # must accept either name (e3q-S928USQS6DZF2 style)
        legacy_h = payloads / "src" / "targets" / PROFILE / "target.h"
        legacy_text = legacy_h.read_text(encoding="utf-8").replace(
            "SLIDE_NFULNL_LOGGER_NAME_OFF", "SLIDE_NFULNL_LOGGER_OFF"
        ).replace(
            "SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF", "SLIDE_RANDOM_BOOT_ID_DATA_OFF"
        )
        legacy_h.write_text(legacy_text, encoding="utf-8", newline="")
        run(["validate-port", "--payloads-repo", str(payloads), "--profile", PROFILE,
             "--version", FOUR_PART, "--kernel-version", KERNEL_VERSION,
             "--kernel-release", "6.1.157-android14-11",
             "--kernel", str(w / PROFILE / "kernel"),
             "--btf", str(btf_path),
             "--kernelsu-path", str(payloads / "kernelsu" / "ksud-s25u-kdp"),
             "--release-size-max", "200000"], cwd=REPO)
        legacy_h.write_bytes(original_target_h)
        print("PASS validate-port: legacy macro names (SLIDE_NFULNL_LOGGER_OFF / SLIDE_RANDOM_BOOT_ID_DATA_OFF) accepted")

        run(["validate-analysis", "--payloads-repo", str(payloads), "--profile", PROFILE,
             "--vmlinux-nm", str(nm_path), "--struct-offsets", str(so_path),
             "--kernel-release", "6.1.157-android14-11"], cwd=REPO)
        run(["checklist", "--payloads-repo", str(payloads), "--profile", PROFILE], cwd=REPO)
        print("PASS validate-analysis + checklist: symbol and BTF cross-checks against derived header")

        # alias-style headers (a36xq/A56) define FAKE_TASK_* as aliases of
        # TASK_*; validate-analysis must resolve them instead of demanding
        # literal values
        alias_h = payloads / "src" / "targets" / PROFILE / "target.h"
        alias_text = alias_h.read_text(encoding="utf-8")
        for fake, task in [
            ("FAKE_TASK_USAGE_OFF", "TASK_USAGE_OFF"),
            ("FAKE_TASK_PI_LOCK_OFF", "TASK_PI_LOCK_OFF"),
            ("FAKE_TASK_PI_WAITERS_OFF", "TASK_PI_WAITERS_OFF"),
        ]:
            m = re.search(rf"^#define\s+{fake}\s+0x([0-9a-fA-F]+)", alias_text, re.M)
            assert m, f"header missing literal {fake}"
            alias_text = alias_text.replace(
                f"#define {fake} 0x{m.group(1)}",
                f"#define {task} 0x{m.group(1)}\n#define {fake} {task}",
            )
        alias_h.write_text(alias_text, encoding="utf-8", newline="")
        run(["validate-analysis", "--payloads-repo", str(payloads), "--profile", PROFILE,
             "--vmlinux-nm", str(nm_path), "--struct-offsets", str(so_path),
             "--kernel-release", "6.1.157-android14-11"], cwd=REPO)
        alias_h.write_bytes(original_target_h)
        print("PASS validate-analysis: FAKE_TASK_* alias definitions resolved against BTF")

        # 3b. kernel version vs detected release cross-check
        proc = subprocess.run(CLI + ["validate-port", "--payloads-repo", str(payloads), "--profile", PROFILE,
                                     "--version", FOUR_PART, "--kernel-version", "6.2.0",
                                     "--kernel-release", "6.1.157-android14-11",
                                     "--kernel", str(w / PROFILE / "kernel"),
                                     "--kernelsu-path", str(payloads / "kernelsu" / "ksud-s25u-kdp"),
                                     "--release-size-max", "200000"],
                              cwd=REPO, capture_output=True, text=True)
        assert proc.returncode != 0 and "does not match the leading" in proc.stdout + proc.stderr
        print("PASS kernel version gate: feed kernelVersions must match leading 3 parts of the release")

        # 4. fingerprint provenance: --fingerprint fills in a missing fota.zip,
        # and validate-port downgrades a wrong-AP fingerprint to a loud warning
        bad_dir = work / "bad-target"
        bad_dir.mkdir()
        run(["gen-target-h", "--target-dir", str(bad_dir), "--template", str(TEMPLATE),
             "--profile", PROFILE,
             "--fingerprint", "samsung/r12sksx/essi:16/BP4A.251205.006/ZZ999:user/release-keys",
             "--elf-base", hex(KIMAGE_TEXT_BASE)], cwd=REPO)
        bad_hdr = (bad_dir / "target.h").read_text(encoding="utf-8")
        # the fingerprint may sit on a backslash-continuation line
        assert "ZZ999" in bad_hdr and "S721NKSSCDZF3" not in bad_hdr
        # swap it into the payloads repo: the AP build mismatch is a warning, not a failure
        (payloads / "src" / "targets" / PROFILE / "target.h").write_text(bad_hdr, encoding="utf-8")
        proc = subprocess.run(CLI + ["validate-port", "--payloads-repo", str(payloads), "--profile", PROFILE,
                                     "--version", FOUR_PART, "--kernel-version", KERNEL_VERSION,
                                     "--kernel", str(w / PROFILE / "kernel"),
                                     "--kernelsu-path", str(payloads / "kernelsu" / "ksud-s25u-kdp"),
                                     "--release-size-max", "200000"],
                              cwd=REPO, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "BUILD_FINGERPRINT does not contain AP build" in proc.stdout + proc.stderr
        print("PASS fingerprint provenance: --fingerprint fills the header; wrong-AP is a warning")

        print("ALL PIPELINE CHECKS PASSED")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
