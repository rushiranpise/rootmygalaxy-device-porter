from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path


@dataclass
class PortPlan:
    profile: str
    model: str
    region: str
    version: str | None = None
    firmware_zip: str | None = None
    boot_sha256: str | None = None
    kernel_sha256: str | None = None
    kernel_size: int | None = None
    kernel_release: str | None = None
    build_fingerprint: str | None = None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rmg-port")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Create a per-device port plan")
    p.add_argument("--profile", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--region", required=True)
    p.add_argument("--version")
    p.add_argument("--workdir", required=True, type=Path)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("extract-kernel", help="Extract boot.img and raw kernel")
    p.add_argument("--firmware-zip", required=True, type=Path)
    p.add_argument("--workdir", required=True, type=Path)
    p.set_defaults(func=cmd_extract_kernel)

    p = sub.add_parser("extract-btf", help="Extract a validated raw BTF blob from a kernel Image")
    p.add_argument("--kernel", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_extract_btf)

    p = sub.add_parser("gen-p0", help="Generate p0_fingerprint.h")
    p.add_argument("--kernel", required=True, type=Path)
    p.add_argument("--probe-offset", required=True)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_gen_p0)

    p = sub.add_parser("scaffold-target", help="Create src/targets/<profile> skeleton")
    p.add_argument("--payloads-repo", required=True, type=Path)
    p.add_argument("--profile", required=True)
    p.add_argument("--source-target", required=True)
    p.add_argument("--p0-header", type=Path)
    p.add_argument("--replace-existing", action="store_true")
    p.add_argument("--write-readme", action="store_true")
    p.set_defaults(func=cmd_scaffold_target)

    p = sub.add_parser("write-port-doc", help="Write a generated docs/<model>-<build>.md stub")
    p.add_argument("--payloads-repo", required=True, type=Path)
    p.add_argument("--profile", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--region", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--kernel", type=Path)
    p.add_argument("--kernel-release")
    p.set_defaults(func=cmd_write_port_doc)

    p = sub.add_parser("add-feed-entry", help="Add or replace one targets-v3.json payload entry")
    p.add_argument("--payloads-repo", required=True, type=Path)
    p.add_argument("--profile", required=True)
    p.add_argument("--payload-id")
    p.add_argument("--display-name", required=True)
    p.add_argument("--model", required=True, action="append")
    p.add_argument("--kernel-version", required=True, action="append")
    p.add_argument("--exploit-path", required=True, type=Path)
    p.add_argument("--kernelsu-path", required=True, type=Path)
    p.add_argument("--preserve-existing-metadata", action="store_true")
    p.add_argument("--requires-fresh-p0-session", action="store_true")
    p.set_defaults(func=cmd_add_feed_entry)

    p = sub.add_parser("validate-feed", help="Validate targets-v3 artifact sizes")
    p.add_argument("--payloads-repo", required=True, type=Path)
    p.set_defaults(func=cmd_validate_feed)

    p = sub.add_parser("validate-port", help="Run offline gates before opening a payload PR")
    p.add_argument("--payloads-repo", required=True, type=Path)
    p.add_argument("--profile", required=True)
    p.add_argument("--payload-id")
    p.add_argument("--version", required=True)
    p.add_argument("--kernel-version", required=True)
    p.add_argument("--allow-profile-build-mismatch", action="store_true")
    p.set_defaults(func=cmd_validate_port)

    p = sub.add_parser("checklist", help="Print the remaining PR checklist")
    p.add_argument("--payloads-repo", required=True, type=Path)
    p.add_argument("--profile", required=True)
    p.set_defaults(func=cmd_checklist)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_init(args: argparse.Namespace) -> int:
    args.workdir.mkdir(parents=True, exist_ok=True)
    plan = PortPlan(args.profile, args.model, args.region, args.version)
    plan_path = args.workdir / "port-plan.json"
    plan_path.write_text(json.dumps(asdict(plan), indent=2) + "\n", encoding="utf-8")
    print(f"created {plan_path}")
    return 0


def cmd_extract_kernel(args: argparse.Namespace) -> int:
    args.workdir.mkdir(parents=True, exist_ok=True)
    ap_member = extract_ap_archive(args.firmware_zip, args.workdir)
    boot_lz4 = extract_from_tar(ap_member, "boot.img.lz4", args.workdir)
    boot = decompress_lz4(boot_lz4)
    boot_path = args.workdir / "boot.img"
    boot_path.write_bytes(boot)
    kernel_size = struct.unpack_from("<I", boot, 0x08)[0]
    kernel = boot[0x1000 : 0x1000 + kernel_size]
    kernel_path = args.workdir / "kernel"
    kernel_path.write_bytes(kernel)
    print(f"boot.img sha256: {sha256_file(boot_path)}")
    print(f"kernel size: {kernel_size}")
    print(f"kernel sha256: {sha256_file(kernel_path)}")
    return 0


def extract_ap_archive(firmware_zip: Path, workdir: Path) -> Path:
    with zipfile.ZipFile(firmware_zip) as archive:
        names = archive.namelist()
        ap_names = [name for name in names if Path(name).name.startswith("AP_")]
        if not ap_names:
            raise ValueError("no AP_*.tar.md5 found in firmware zip")
        ap_name = ap_names[0]
        out = workdir / Path(ap_name).name
        with archive.open(ap_name) as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        return out


def extract_from_tar(tar_path: Path, member_suffix: str, workdir: Path) -> Path:
    with tarfile.open(tar_path) as archive:
        members = [m for m in archive.getmembers() if m.name.endswith(member_suffix)]
        if not members:
            raise ValueError(f"{member_suffix} not found in {tar_path}")
        member = members[0]
        out = workdir / Path(member.name).name
        src = archive.extractfile(member)
        if src is None:
            raise ValueError(f"cannot extract {member.name}")
        with out.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        return out


def decompress_lz4(path: Path) -> bytes:
    try:
        import lz4.frame  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("install optional dependency with: python -m pip install -e .[lz4]") from exc
    return lz4.frame.decompress(path.read_bytes())


def cmd_extract_btf(args: argparse.Namespace) -> int:
    image = args.kernel.read_bytes()
    prefix = b"\x9f\xeb\x01\x00"
    candidates: list[tuple[int, int]] = []
    cursor = 0
    while True:
        start = image.find(prefix, cursor)
        if start < 0:
            break
        cursor = start + 1
        if start + 24 > len(image):
            continue
        magic, version, flags, header_len, type_off, type_len, str_off, str_len = struct.unpack_from(
            "<HBBIIIII", image, start
        )
        if magic != 0xEB9F or version != 1 or flags != 0 or header_len < 24:
            continue
        payload_len = max(type_off + type_len, str_off + str_len)
        end = start + header_len + payload_len
        string_start = start + header_len + str_off
        if end <= len(image) and string_start < end and image[string_start] == 0:
            candidates.append((start, end))
    if len(candidates) != 1:
        raise ValueError(f"expected one raw BTF blob, found {candidates}")
    start, end = candidates[0]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(image[start:end])
    print(f"raw BTF: [0x{start:x}, 0x{end:x}) ({end - start} bytes)")
    return 0


def cmd_gen_p0(args: argparse.Namespace) -> int:
    probe_offset = parse_int(args.probe_offset)
    image = args.kernel.read_bytes()
    page_offsets = [0x000, 0x200, 0x400, 0x600, 0x800, 0xA00, 0xC00, 0xE00]
    rows: list[tuple[int, list[int]]] = []
    for slide in [i * 0x10000 for i in range(32)]:
        page_source = probe_offset - slide
        if page_source < 0:
            raise ValueError(f"slide 0x{slide:x} exceeds probe offset 0x{probe_offset:x}")
        words = []
        for page_offset in page_offsets:
            source = page_source + page_offset
            if source + 8 > len(image):
                raise ValueError(f"source offset 0x{source:x} exceeds kernel image")
            words.append(struct.unpack_from("<Q", image, source)[0])
        rows.append((slide, words))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_p0_header(probe_offset, page_offsets, rows), encoding="utf-8")
    print(f"verified 32 rows and 256 source qwords at probe 0x{probe_offset:x}")
    return 0


def render_p0_header(probe_offset: int, page_offsets: list[int], rows: list[tuple[int, list[int]]]) -> str:
    lines = [
        "// Generated from the exact raw Image.",
        f"// Each row maps actual slide to Image[0x{probe_offset:x} - slide].",
        "#ifndef P0_FINGERPRINT_H",
        "#define P0_FINGERPRINT_H",
        "",
        "#define P0_FINGERPRINT_WORDS 8",
        "",
        "static const uint16_t p0_fingerprint_offsets[P0_FINGERPRINT_WORDS] = {",
        "  " + ", ".join(f"0x{x:03x}" for x in page_offsets) + ",",
        "};",
        "",
        "struct p0_fingerprint {",
        "  uintptr_t slide;",
        "  uint64_t words[P0_FINGERPRINT_WORDS];",
        "};",
        "",
        "static const struct p0_fingerprint p0_fingerprints[] = {",
    ]
    for slide, words in rows:
        lines.append(f"  {{ 0x{slide:06x}ULL, {{ " + ", ".join(f"0x{w:016x}ULL" for w in words) + " } },")
    lines.extend(["};", "", "#endif", ""])
    return "\n".join(lines)


def cmd_scaffold_target(args: argparse.Namespace) -> int:
    targets = args.payloads_repo / "src" / "targets"
    src = targets / args.source_target
    dst = targets / args.profile
    if not src.exists():
        raise ValueError(f"source target does not exist: {src}")
    if dst.exists():
        if not args.replace_existing:
            raise ValueError(f"target already exists: {dst}")
        if src.resolve() == dst.resolve():
            backup = targets / f"{args.profile}.source-backup"
            if backup.exists():
                shutil.rmtree(backup)
            shutil.copytree(src, backup)
            src = backup
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    if args.p0_header:
        shutil.copyfile(args.p0_header, dst / "p0_fingerprint.h")
    readme = dst / "README.md"
    if args.write_readme and not readme.exists():
        readme.write_text(
            f"# {args.profile}\n\n"
            "Porting notes must record firmware identity, hashes, offset sources, "
            "build commands, KernelSU audit, and hardware validation status.\n",
            encoding="utf-8",
        )
    print(f"created {dst}")
    print("review target.h now; copied offsets are placeholders until independently derived")
    return 0


def cmd_write_port_doc(args: argparse.Namespace) -> int:
    docs = args.payloads_repo / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    build = args.version.split("/", 1)[0]
    doc = docs / f"{args.model}-{build}.md"
    kernel_sha = sha256_file(args.kernel) if args.kernel and args.kernel.exists() else "TODO"
    kernel_size = args.kernel.stat().st_size if args.kernel and args.kernel.exists() else "TODO"
    doc.write_text(
        f"# {args.model} {build}\n\n"
        "Generated by Root My Galaxy Device Porter.\n\n"
        "## Firmware Identity\n\n"
        f"- Profile: `{args.profile}`\n"
        f"- Model: `{args.model}`\n"
        f"- Region: `{args.region}`\n"
        f"- Samsung version: `{args.version}`\n"
        f"- Kernel release: `{args.kernel_release or 'TODO'}`\n"
        f"- Raw kernel size: `{kernel_size}`\n"
        f"- Raw kernel SHA-256: `{kernel_sha}`\n\n"
        "## Required Manual Review\n\n"
        "- Replace scaffolded `target.h` offsets with values derived from this exact firmware.\n"
        "- Confirm tracefs event ID, worker caller offset, and pselect word shift.\n"
        "- Build and audit the exact KernelSU module and late-load binary.\n"
        "- Run hardware validation on an owned or explicitly authorized device.\n",
        encoding="utf-8",
    )
    print(f"wrote {doc}")
    return 0


def cmd_add_feed_entry(args: argparse.Namespace) -> int:
    repo = args.payloads_repo
    payload_id = args.payload_id or args.profile
    feed_path = repo / "support" / "targets-v3.json"
    data = json.loads(feed_path.read_text(encoding="utf-8"))
    existing_entries = [p for p in data.get("payloads", []) if p.get("payloadId") == payload_id]
    existing = existing_entries[0] if existing_entries else {}
    exploit_rel = args.exploit_path.resolve().relative_to(repo.resolve()).as_posix()
    kernelsu_rel = args.kernelsu_path.resolve().relative_to(repo.resolve()).as_posix()
    entry = {
        "payloadId": payload_id,
        "displayName": existing.get("displayName", args.display_name)
        if args.preserve_existing_metadata
        else args.display_name,
        "models": existing.get("models", sorted(set(args.model)))
        if args.preserve_existing_metadata
        else sorted(set(args.model)),
        "kernelVersions": existing.get("kernelVersions", sorted(set(args.kernel_version)))
        if args.preserve_existing_metadata
        else sorted(set(args.kernel_version)),
        "exploit": {
            "url": f"https://raw.githubusercontent.com/BuSung-dev/Root-My-Galaxy-Payloads/main/{exploit_rel}",
            "size": args.exploit_path.stat().st_size,
        },
        "kernelsu": {
            "url": f"https://raw.githubusercontent.com/BuSung-dev/Root-My-Galaxy-Payloads/main/{kernelsu_rel}",
            "size": args.kernelsu_path.stat().st_size,
        },
    }
    if args.preserve_existing_metadata and "requiresFreshP0Session" in existing:
        entry["requiresFreshP0Session"] = existing["requiresFreshP0Session"]
    elif args.requires_fresh_p0_session:
        entry["requiresFreshP0Session"] = True
    payloads = [p for p in data.get("payloads", []) if p.get("payloadId") != payload_id]
    payloads.append(entry)
    data["payloads"] = payloads
    feed_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"updated {feed_path}")
    return 0


def cmd_validate_feed(args: argparse.Namespace) -> int:
    feed_path = args.payloads_repo / "support" / "targets-v3.json"
    data = json.loads(feed_path.read_text(encoding="utf-8"))
    if data.get("schemaVersion") != 3:
        raise ValueError("schemaVersion must be 3")
    errors = 0
    for payload in data.get("payloads", []):
        for field in ("exploit", "kernelsu"):
            asset = payload[field]
            size = int(asset["size"])
            local = local_path_from_raw_url(args.payloads_repo, asset["url"])
            if local and local.exists():
                actual = local.stat().st_size
                if actual != size:
                    print(f"size mismatch: {payload['payloadId']} {field}: feed={size} actual={actual}")
                    errors += 1
            else:
                print(f"warning: cannot resolve local asset for {payload['payloadId']} {field}")
    if errors:
        return 1
    print("support feed OK")
    return 0


def cmd_validate_port(args: argparse.Namespace) -> int:
    repo = args.payloads_repo
    profile = args.profile
    payload_id = args.payload_id or profile
    ap_build = args.version.split("/", 1)[0]
    target_dir = repo / "src" / "targets" / profile
    target_h = target_dir / "target.h"
    p0_h = target_dir / "p0_fingerprint.h"
    artifact = repo / "artifacts" / profile / "cve-2026-43499-app.so"

    errors: list[str] = []
    if not target_h.exists():
        errors.append(f"missing target header: {target_h}")
    if not p0_h.exists():
        errors.append(f"missing P0 fingerprint: {p0_h}")
    if not artifact.exists():
        errors.append(f"missing release payload: {artifact}")

    if not args.allow_profile_build_mismatch and ap_build not in profile:
        errors.append(
            f"firmware AP build {ap_build} does not match profile {profile}; "
            "use an exact profile for this firmware instead of replacing another build"
        )

    target_text = target_h.read_text(encoding="utf-8", errors="replace") if target_h.exists() else ""
    fingerprint_match = re.search(r'#define\s+BUILD_FINGERPRINT\s+"([^"]+)"', target_text)
    if fingerprint_match:
        fingerprint = fingerprint_match.group(1)
        if ap_build not in fingerprint:
            errors.append(f"BUILD_FINGERPRINT does not contain AP build {ap_build}: {fingerprint}")
    else:
        errors.append("target.h does not define BUILD_FINGERPRINT")

    expected_p0_include = f'targets/{profile}/p0_fingerprint.h'
    if target_text and expected_p0_include not in target_text:
        errors.append(f"target.h does not reference {expected_p0_include}")

    p0_text = p0_h.read_text(encoding="utf-8", errors="replace") if p0_h.exists() else ""
    rows = re.findall(r"\{\s*0x[0-9a-fA-F]{6}ULL,\s*\{", p0_text)
    if p0_text and len(rows) != 32:
        errors.append(f"p0_fingerprint.h should contain 32 slide rows, found {len(rows)}")

    feed_path = repo / "support" / "targets-v3.json"
    data = json.loads(feed_path.read_text(encoding="utf-8"))
    entries = [p for p in data.get("payloads", []) if p.get("payloadId") == payload_id]
    if len(entries) != 1:
        errors.append(f"support feed should contain exactly one entry for {payload_id}, found {len(entries)}")
    elif args.kernel_version not in entries[0].get("kernelVersions", []):
        errors.append(f"support feed entry does not include kernel version {args.kernel_version}")

    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("offline port gates OK")
    return 0


def local_path_from_raw_url(repo: Path, url: str) -> Path | None:
    marker = "/Root-My-Galaxy-Payloads/main/"
    if marker not in url:
        return None
    return repo / url.split(marker, 1)[1]


def cmd_checklist(args: argparse.Namespace) -> int:
    profile = args.profile
    repo = args.payloads_repo
    checks = [
        (repo / "src" / "targets" / profile / "target.h", "target header exists"),
        (repo / "src" / "targets" / profile / "p0_fingerprint.h", "P0 fingerprint exists"),
        (repo / "artifacts" / profile / "cve-2026-43499-app.so", "release app payload exists"),
        (repo / "support" / "targets-v3.json", "support feed updated and validated"),
        (repo / "docs", "porting doc added with firmware hashes and validation notes"),
    ]
    for path, label in checks:
        mark = "OK" if path.exists() else "TODO"
        print(f"[{mark}] {label}: {path}")
    print("[TODO] derive target.h offsets from target vmlinux/BTF, not copied profiles")
    print("[TODO] build and audit exact KernelSU KO plus ksud late-load artifact")
    print("[TODO] run hardware validation on an owned or authorized device")
    print("[TODO] open PR with generated artifacts, support feed, and docs")
    return 0


def parse_int(value: str) -> int:
    return int(value, 16 if value.lower().startswith("0x") else 10)


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
