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
        header = (payloads / "src" / "targets" / PROFILE / "target.h").read_text(encoding="utf-8")
        assert FINGERPRINT in header
        assert f"targets/{PROFILE}/p0_fingerprint.h" in header
        report = (payloads / "src" / "targets" / PROFILE / "port-report.md").read_text(encoding="utf-8")
        derived = sum(1 for l in report.splitlines() if l.startswith("- [DERIVED]"))
        assert derived >= 50, f"only {derived} derived entries"
        print(f"PASS scaffold+derive: target.h written with {derived} derived macros")

        # 3. fake artifacts + feed entry + validation gates
        (payloads / "artifacts" / PROFILE).mkdir(parents=True)
        (payloads / "artifacts" / PROFILE / "cve-2026-43499-app.so").write_bytes(b"\x00" * 104128)
        run(["add-feed-entry", "--payloads-repo", str(payloads), "--profile", PROFILE,
             "--display-name", "Galaxy Test | Kernel 6.1.157",
             "--model", "SM-S721N", "--kernel-version", KERNEL_VERSION,
             "--exploit-path", str(payloads / "artifacts" / PROFILE / "cve-2026-43499-app.so"),
             "--kernelsu-path", str(payloads / "kernelsu" / "ksud-s25u-kdp")], cwd=REPO)
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

        run(["validate-analysis", "--payloads-repo", str(payloads), "--profile", PROFILE,
             "--vmlinux-nm", str(nm_path), "--struct-offsets", str(so_path),
             "--kernel-release", "6.1.157-android14-11"], cwd=REPO)
        run(["checklist", "--payloads-repo", str(payloads), "--profile", PROFILE], cwd=REPO)
        print("PASS validate-analysis + checklist: symbol and BTF cross-checks against derived header")

        # 4. a wrong-AP fingerprint in the payloads repo header must fail validate-port
        bad = work / "bad-fingerprint.json"
        bad.write_text(json.dumps({"fingerprint": "samsung/r12sksx/essi:16/BP4A.251205.006/ZZ999:user/release-keys"}),
                       encoding="utf-8")
        bad_dir = work / "bad-target"
        bad_dir.mkdir()
        run(["gen-target-h", "--target-dir", str(bad_dir), "--template", str(TEMPLATE),
             "--profile", PROFILE, "--fota-props", str(bad), "--elf-base", hex(KIMAGE_TEXT_BASE)], cwd=REPO)
        bad_hdr = (bad_dir / "target.h").read_text(encoding="utf-8")
        fingerprint_line = next(
            l for l in bad_hdr.splitlines() if l.strip().startswith("#define BUILD_FINGERPRINT")
        )
        assert "ZZ999" in fingerprint_line and "S721NKSSCDZF3" not in fingerprint_line
        # swap it into the payloads repo: the AP build check must now fail
        (payloads / "src" / "targets" / PROFILE / "target.h").write_text(bad_hdr, encoding="utf-8")
        proc = subprocess.run(CLI + ["validate-port", "--payloads-repo", str(payloads), "--profile", PROFILE,
                                     "--version", FOUR_PART, "--kernel-version", KERNEL_VERSION,
                                     "--kernel", str(w / PROFILE / "kernel"),
                                     "--kernelsu-path", str(payloads / "kernelsu" / "ksud-s25u-kdp"),
                                     "--release-size-max", "200000"],
                              cwd=REPO, capture_output=True, text=True)
        assert proc.returncode != 0 and "BUILD_FINGERPRINT does not contain AP build" in proc.stdout + proc.stderr
        print("PASS fingerprint gate: validate-port rejects a wrong-AP BUILD_FINGERPRINT")

        print("ALL PIPELINE CHECKS PASSED")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
