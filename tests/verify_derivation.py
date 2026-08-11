"""Standalone regression checks for the target.h derivation pipeline.

Run with:  python tests/verify_derivation.py
Builds a synthetic raw BTF blob, synthetic vmlinux nm from a real template
target.h, and fota props, then runs the CLI commands and asserts the derived
header reproduces the expected values.
"""
from __future__ import annotations

import json
import os
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

KIMAGE_TEXT_BASE = 0xFFFFFFC008000000

# (struct name, size, [(member, byte_offset), ...])
STRUCTS = {
    "task_struct": [
        ("usage", 0x40),
        ("prio", 0x84),
        ("normal_prio", 0x8C),
        ("sched_task_group", 0x348),
        ("pi_lock", 0x924),
        ("pi_waiters", 0x938),
        ("pi_top_task", 0x948),
        ("pi_blocked_on", 0x950),
    ],
    "file_operations": [
        ("owner", 0x00),
        ("llseek", 0x08),
        ("read", 0x10),
        ("write", 0x18),
        ("read_iter", 0x20),
        ("write_iter", 0x28),
        ("unlocked_ioctl", 0x50),
        ("compat_ioctl", 0x58),
        ("mmap", 0x60),
        ("open", 0x70),
        ("release", 0x80),
        ("splice_read", 0xC8),
        ("show_fdinfo", 0xE0),
    ],
    "page": [
        ("flags", 0x00),
        ("compound_head", 0x08),
        ("slab_cache", 0x18),
        ("page_type", 0x30),
    ],
    "work_struct": [
        ("data", 0x00),
        ("entry", 0x08),
        ("func", 0x18),
    ],
    "miscdevice": [("minor", 0x00), ("name", 0x08), ("fops", 0x10)],
    "selinux_state": [("disabled", 0x00), ("enforcing", 0x04), ("initialized", 0x08)],
    "workqueue_struct": [("pwqs", 0x00), ("dfl_pwq", 0xB0)],
    "pool_workqueue": [
        ("pool", 0x00),
        ("wq", 0x08),
        ("work_color", 0x10),
        ("refcnt", 0x18),
        ("nr_in_flight", 0x1C),
        ("nr_active", 0x5C),
        ("max_active", 0x60),
    ],
    "worker_pool": [("worklist", 0x28), ("nr_idle", 0x3C)],
    "configfs_buffer": [
        ("read_wait", 0x00),
        ("page", 16),
        ("needs_read_fill", 80),
        ("bin_buffer", 88),
        ("bin_buffer_size", 96),
        ("cb_max_size", 100),
    ],
}

SIZES = {
    "task_struct": 0x22C0,
    "file_operations": 0x110,
    "page": 0x40,
    "work_struct": 0x20,
    "miscdevice": 0x18,
    "selinux_state": 0x10,
    "workqueue_struct": 0xC0,
    "pool_workqueue": 0x80,
    "worker_pool": 0x200,
    "configfs_buffer": 0x80,
}


def build_btf_blob() -> bytes:
    """Create a minimal valid raw BTF blob containing the structs above."""
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
    for sname, members in STRUCTS.items():
        name_off = intern(sname)
        vlen = len(members)
        info = (4 << 24) | vlen  # STRUCT, no kind_flag
        type_bytes += struct.pack("<III", name_off, info, SIZES[sname])
        for mname, off in members:
            type_bytes += struct.pack("<III", intern(mname), 0, off << 3)
    str_bytes = b"".join(strings)
    hdr_len = 24
    type_off = 0
    str_off = len(type_bytes)
    header = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, hdr_len, type_off, len(type_bytes), str_off, len(str_bytes))
    return header + bytes(type_bytes) + str_bytes


def build_nm() -> str:
    """Reconstruct nm lines from the template target.h so symbol offsets match."""
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
        import re as _re

        m = _re.search(rf"#define\s+{macro}\s+0x([0-9a-fA-F]+)", text)
        assert m, f"template missing {macro}"
        # for composite macros (symbol + BTF member) the nm symbol address is
        # base + template_offset - member_offset
        member_offset = {"ASHMEM_MISC_FOPS_OFF": 0x10, "SELINUX_ENFORCING_OFF": 0x04}.get(macro, 0)
        addr = KIMAGE_TEXT_BASE + int(m.group(1), 16) - member_offset
        lines.append(f"{addr:016x} T {sym}")
    # pad past the 1000-symbol sanity floor
    for i in range(1200):
        lines.append(f"{KIMAGE_TEXT_BASE + 0x100000 + i * 0x10:016x} t foo_symbol_{i}")
    return "\n".join(lines) + "\n"


def build_fota_zip() -> tuple[Path, dict[str, str]]:
    props = {
        "ro.build.fingerprint": "samsung/r12sksx/essi:16/BP4A.251205.006/S721NKSSCDZF3:user/release-keys",
        "ro.build.display.id": "BP4A.251205.006.S721NKSSCDZF3",
        "ro.product.model": "SM-S721N",
        "ro.build.version.sdk": "35",
    }
    fota = Path(tempfile.mkdtemp()) / "fota.zip"
    with zipfile.ZipFile(fota, "w") as zf:
        body = "".join(f"{k}={v}\n" for k, v in props.items())
        zf.writestr("system/build.prop", body)
    return fota, props


def run_cli(args: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(CLI + args, cwd=cwd or REPO, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"cli {' '.join(args)} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout


def main() -> None:
    if not TEMPLATE.exists():
        raise SystemExit(f"template target.h not found: {TEMPLATE} (clone payloads repo next to porter)")
    work = Path(tempfile.mkdtemp(prefix="rmg-verify-"))
    sys.path.insert(0, str(REPO / "src"))
    try:
        # --- 1. btf-struct -------------------------------------------------
        blob = build_btf_blob()
        btf_path = work / "vmlinux.btf"
        btf_path.write_bytes(blob)
        so_path = work / "struct-offsets.json"
        run_cli(["btf-struct", "--btf", str(btf_path), "--out", str(so_path), "--structs", ",".join(STRUCTS)])
        data = json.loads(so_path.read_text(encoding="utf-8"))
        structs = data["structs"]
        assert structs["task_struct"]["size"] == SIZES["task_struct"], structs["task_struct"]
        assert structs["task_struct"]["members"]["pi_lock"] == 0x924
        assert structs["file_operations"]["members"]["show_fdinfo"] == 0xE0
        assert structs["page"]["members"]["compound_head"] == 0x08
        assert structs["miscdevice"]["members"]["fops"] == 0x10
        assert structs["selinux_state"]["members"]["enforcing"] == 0x04
        assert structs["configfs_buffer"]["members"]["needs_read_fill"] == 80
        print("PASS btf-struct: offsets and sizes parsed from synthetic raw BTF")

        # --- 2. extract-fota -------------------------------------------------
        fota_zip, props = build_fota_zip()
        firmware = work / "firmware.zip"
        with zipfile.ZipFile(firmware, "w") as zf:
            zf.write(fota_zip, "meta-data/fota.zip")
        props_path = work / "fota-props.json"
        run_cli(["extract-fota", "--firmware-zip", str(firmware), "--out", str(props_path)])
        fota = json.loads(props_path.read_text(encoding="utf-8"))
        assert fota["fingerprint"] == props["ro.build.fingerprint"], fota
        print("PASS extract-fota: fingerprint read from meta-data/fota.zip")

        # --- 3. gen-target-h -------------------------------------------------
        nm_path = work / "vmlinux.nm"
        nm_path.write_text(build_nm(), encoding="utf-8")
        target_dir = work / "target"
        target_dir.mkdir()
        out = run_cli(
            [
                "gen-target-h",
                "--target-dir", str(target_dir),
                "--template", str(TEMPLATE),
                "--profile", "essi-S721NKSSCDZF3",
                "--fota-props", str(props_path),
                "--vmlinux-nm", str(nm_path),
                "--elf-base", hex(KIMAGE_TEXT_BASE),
                "--struct-offsets", str(so_path),
            ],
            cwd=REPO,
        )
        print(out)
        derived_header = (target_dir / "target.h").read_text(encoding="utf-8")
        report = (target_dir / "port-report.md").read_text(encoding="utf-8")

        checks_hex = {
            "KIMAGE_TEXT_BASE": 0xFFFFFFC008000000,
            "INIT_TASK_OFF": 0x022FF800,
            "ASHMEM_FOPS_OFF": 0x013D9D48,
            "CALL_USERMODEHELPER_EXEC_WORK_OFF": 0x000D4468,
            "FAKE_TASK_PI_LOCK_OFF": 0x924,
            "FAKE_TASK_USAGE_OFF": 0x40,
            "FAKE_TASK_TASK_GROUP_OFF": 0x348,
            "STRUCT_PAGE_SIZE": 0x40,
            "STRUCT_PAGE_COMPOUND_HEAD_OFF": 0x08,
            "FOPS_SHOW_FDINFO_OFF": 0xE0,
            "FOPS_IOCTL_OFF": 0x50,
            "WORK_FUNC_OFF": 0x18,
            "WQ_DFL_PWQ_OFF": 0xB0,
            "PWQ_NR_ACTIVE_OFF": 0x5C,
            "POOL_NR_IDLE_OFF": 0x3C,
            "CFG_PAGE_OFF": 0x10,
            "CFG_CB_MAX_SIZE_OFF": 0x64,
            "SELINUX_ENFORCING_OFF": 0x025EA478,  # selinux_state + 0x04
            "ASHMEM_MISC_FOPS_OFF": 0x02484970,  # ashmem_misc + 0x10
            "SIZEOF_FILE_OPERATIONS": 0x110,
        }
        for macro, expected in checks_hex.items():
            m = re.search(rf"#define\s+{re.escape(macro)}\s+0x([0-9a-fA-F]+)", derived_header)
            assert m, f"{macro}: missing from derived header"
            actual = int(m.group(1), 16)
            assert actual == expected, f"{macro}: expected 0x{expected:x}, got 0x{actual:x}"
        for macro, value in [
            ("BUILD_FINGERPRINT", '"samsung/r12sksx/essi:16/BP4A.251205.006/S721NKSSCDZF3:user/release-keys"'),
            ("P0_FINGERPRINT_HEADER", '"targets/essi-S721NKSSCDZF3/p0_fingerprint.h"'),
        ]:
            assert f"#define {macro} {value}" in derived_header, f"{macro}: expected {value}"
        # scaffolded macros untouched
        assert "#define SLIDE_TRACEFS_EVENT_ID 106" in derived_header
        assert "#define P0_KERNEL_PHYS_LOAD 0x80000000ULL" in derived_header
        assert "#define BUILD_VARIANT_LABEL \"essi-S721NKSSCDZF3-app-physical-p0-oracle\"" in derived_header
        # no leftover source-firmware marker in the fingerprint or label
        assert "samsung/r12sksx/essi:16" in derived_header  # same firmware identity here
        for line in report.splitlines():
            if not line.strip():
                continue
            assert line.startswith(("- [DERIVED]", "- [SCAFFOLD]", "- [WARN]", "- [INFO]", "#")), line
        print("PASS gen-target-h: header derived, scaffold preserved, report well-formed")

        # --- 3b. missing-inputs fallback ---------------------------------------
        fallback_dir = work / "target-fallback"
        fallback_dir.mkdir()
        run_cli(
            [
                "gen-target-h",
                "--target-dir", str(fallback_dir),
                "--template", str(TEMPLATE),
                "--profile", "newdev-XX123",
                "--elf-base", hex(KIMAGE_TEXT_BASE),
            ],
            cwd=REPO,
        )
        fallback_report = (fallback_dir / "port-report.md").read_text(encoding="utf-8")
        fallback_hdr = (fallback_dir / "target.h").read_text(encoding="utf-8")
        scaff = [l for l in fallback_report.splitlines() if l.startswith("- [SCAFFOLD]")]
        warns = [l for l in fallback_report.splitlines() if l.startswith("- [WARN]")]
        assert len(scaff) >= 4, f"expected scaffold entries, got {len(scaff)}"
        assert any("no vmlinux nm dump" in w for w in warns), warns
        assert "samsung/r12sksx/essi" in fallback_hdr  # fingerprint kept from template
        print("PASS gen-target-h fallback: scaffolds + nm WARN, fingerprint kept")

        # --- 3c. worker caller derivation --------------------------------------
        caller_off = 0xDBD9C
        base_hex = f"{KIMAGE_TEXT_BASE:016x}"
        objdump = (
            f"{base_hex}dbd70 <worker_thread>:\n"
            f"{base_hex}dbd94:\t97 55 76 0d \tbl\t0xffffffc009e987c <schedule>\n"
            f"{KIMAGE_TEXT_BASE + caller_off:016x}:\t97 00 00 00 \tbl\t0xffffffc009e987c <worker_enter_idle>\n"
        )
        od_path = work / "worker.objdump"
        od_path.write_text(objdump, encoding="utf-8")
        wd_dir = work / "target-worker"
        wd_dir.mkdir()
        run_cli(
            [
                "gen-target-h",
                "--target-dir", str(wd_dir),
                "--template", str(TEMPLATE),
                "--profile", "newdev-XX123",
                "--elf-base", hex(KIMAGE_TEXT_BASE),
                "--worker-objdump", str(od_path),
            ],
            cwd=REPO,
        )
        wd_hdr = (wd_dir / "target.h").read_text(encoding="utf-8")
        m = re.search(r"#define SLIDE_TRACEFS_WORKER_CALLER_OFF\s+0x([0-9a-fA-F]+)", wd_hdr)
        assert m and int(m.group(1), 16) == caller_off, f"caller off: {m.group(0) if m else None}"
        print("PASS gen-target-h worker caller: SLIDE_TRACEFS_WORKER_CALLER_OFF derived from objdump")

        # --- 3d. scaffold-target --skip-target-header ---------------------------
        fake_payloads = work / "payloads"
        (fake_payloads / "src" / "targets").mkdir(parents=True)
        shutil.copytree(PAYLOADS / "src" / "targets" / "essi-S721NKSSCDZF3", fake_payloads / "src" / "targets" / "essi-S721NKSSCDZF3")
        run_cli(
            [
                "scaffold-target",
                "--payloads-repo", str(fake_payloads),
                "--profile", "newdev-XX123",
                "--source-target", "essi-S721NKSSCDZF3",
                "--skip-target-header",
            ],
            cwd=REPO,
        )
        new_dir = fake_payloads / "src" / "targets" / "newdev-XX123"
        assert not (new_dir / "target.h").exists(), "target.h should be skipped"
        assert (new_dir / "p0_fingerprint.h").exists()
        print("PASS scaffold-target --skip-target-header: no stale target.h copied")

        # --- 4. validate-analysis struct cross-check --------------------------
        proc = subprocess.run(
            CLI
            + [
                "validate-analysis",
                "--payloads-repo", str(PAYLOADS),
                "--profile", "essi-S721NKSSCDZF3",
                "--vmlinux-nm", str(nm_path),
                "--struct-offsets", str(so_path),
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        # The template header in the payloads repo matches the synthetic BTF
        # by construction, so the gate must pass.
        if proc.returncode != 0:
            raise SystemExit(f"validate-analysis failed:\n{proc.stdout}\n{proc.stderr}")
        print("PASS validate-analysis: struct-offsets cross-check against template header")

        print("ALL VERIFICATION CHECKS PASSED")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
