from __future__ import annotations

import argparse
import gzip
import json
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
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

    p = sub.add_parser(
        "samloader-version",
        help="Print the newest stable four-part version from samloader check-update output",
    )
    p.add_argument("--check-update-file", required=True, type=Path)
    p.set_defaults(func=cmd_samloader_version)

    p = sub.add_parser(
        "extract-fota",
        help="Extract firmware identity props (ro.build.fingerprint, display id) from meta-data/fota.zip",
    )
    p.add_argument("--firmware-zip", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=cmd_extract_fota)

    p = sub.add_parser(
        "btf-struct",
        help="Parse a raw BTF blob in pure Python and dump struct sizes and member byte offsets",
    )
    p.add_argument("--btf", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument(
        "--structs",
        required=True,
        help="comma-separated struct names to extract",
    )
    p.set_defaults(func=cmd_btf_struct)

    p = sub.add_parser(
        "gen-target-h",
        help="Derive target.h for this firmware from fota props, recovered vmlinux nm/BTF, and ELF base",
    )
    p.add_argument("--target-dir", required=True, type=Path, help="src/targets/<profile> in the payloads repo")
    p.add_argument("--template", required=True, type=Path, help="source target's target.h used as the header scaffold")
    p.add_argument("--profile", required=True)
    p.add_argument("--fota-props", type=Path)
    p.add_argument("--fingerprint", help="ro.build.fingerprint override, used when fota.zip is unavailable")
    p.add_argument("--vmlinux-nm", type=Path)
    p.add_argument("--vmlinux-elf", type=Path)
    p.add_argument("--elf-base", help="recovered ELF base as hex, overrides ELF segment scan")
    p.add_argument("--struct-offsets", type=Path)
    p.add_argument("--worker-objdump", type=Path)
    p.add_argument("--report", type=Path, help="derivation report output path")
    p.set_defaults(func=cmd_gen_target_h)

    p = sub.add_parser("scaffold-target", help="Create src/targets/<profile> skeleton")
    p.add_argument("--payloads-repo", required=True, type=Path)
    p.add_argument("--profile", required=True)
    p.add_argument("--source-target", required=True)
    p.add_argument("--p0-header", type=Path)
    p.add_argument("--replace-existing", action="store_true")
    p.add_argument("--write-readme", action="store_true")
    p.add_argument(
        "--skip-target-header",
        action="store_true",
        help="copy the scaffold but not the source target.h (use with gen-target-h)",
    )
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
    p.add_argument("--kernelsu-path", type=Path)
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
    p.add_argument("--kernel-release")
    p.add_argument("--kernel", type=Path)
    p.add_argument("--btf", type=Path)
    p.add_argument("--release-size-max", type=int, default=104128)
    p.add_argument("--kernelsu-path", type=Path)
    p.add_argument("--kernelsu-ko-path", type=Path)
    p.add_argument("--allow-profile-build-mismatch", action="store_true")
    p.set_defaults(func=cmd_validate_port)

    p = sub.add_parser("validate-analysis", help="Validate deeper recovered-kernel and KernelSU audit artifacts")
    p.add_argument("--payloads-repo", required=True, type=Path)
    p.add_argument("--profile", required=True)
    p.add_argument("--vmlinux-nm", required=True, type=Path)
    p.add_argument("--btf-raw", type=Path)
    p.add_argument("--worker-objdump", type=Path)
    p.add_argument("--modinfo", type=Path)
    p.add_argument("--kernel-release")
    p.add_argument("--check-symbol-log", type=Path)
    p.add_argument("--module-audit-log", type=Path)
    p.add_argument(
        "--struct-offsets",
        type=Path,
        help="btf-struct JSON; cross-checks BTF-derived macros against the raw BTF",
    )
    p.set_defaults(func=cmd_validate_analysis)

    p = sub.add_parser("checklist", help="Print the remaining PR checklist")
    p.add_argument("--payloads-repo", required=True, type=Path)
    p.add_argument("--profile", required=True)
    p.set_defaults(func=cmd_checklist)

    p = sub.add_parser(
        "device-info",
        help="Capture a connected adb device's identity and emit dispatch-ready port inputs as JSON",
    )
    p.add_argument("--serial", help="adb serial; defaults to the single connected device")
    p.add_argument("--out", type=Path, help="JSON output path (default device-info-<model>-<AP>.json)")
    p.add_argument(
        "--display-name",
        help="support feed display name (default 'Galaxy <model> | Kernel <kernel_version>')",
    )
    p.add_argument(
        "--source-target",
        help="existing target to scaffold from; required for dispatch (kernel-generation match recommended)",
    )
    p.add_argument(
        "--kernelsu-artifact",
        help="existing kernelsu/ ksud path to reuse; required for dispatch unless kernelsu_build=ddk",
    )
    p.add_argument(
        "--version",
        help="four-part firmware version; defaults to the device build, falls back to latest",
    )
    p.add_argument("--cp", help="CP part of the four-part version (defaults to the AP part)")
    p.add_argument("--probe-offset", default="0x1f0000", help="P0 probe offset for p0_fingerprint.h")
    p.add_argument(
        "--check-update",
        action="store_true",
        help="run 'samloader check-update' and record the FUS latest version",
    )
    p.add_argument(
        "--probe-fus",
        action="store_true",
        help="probe whether the device build is still served by Samsung FUS (short download probe)",
    )
    p.set_defaults(func=cmd_device_info)

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


FOUR_PART_VERSION = r"[A-Z0-9]+/[A-Z0-9]+/[A-Z0-9]+/[A-Z0-9]+"


def cmd_samloader_version(args: argparse.Namespace) -> int:
    text = args.check_update_file.read_text(encoding="utf-8", errors="replace")
    # samloader-rs check-update --all prints:
    #   Latest Stable Version:
    #   <version>            (value on the NEXT line, and may be empty)
    #   Previous Stable Versions (sorted from new to old):
    #   <version>
    #   ...
    #   Beta Versions ...
    # Match the value directly under the label first; when the label is empty
    # (no stable version reported), fall back to the newest previous stable.
    match = re.search(r"Latest Stable Version:\s*(" + FOUR_PART_VERSION + r")", text)
    if not match:
        match = re.search(
            r"Previous Stable Versions[^\n]*\n\s*(" + FOUR_PART_VERSION + r")",
            text,
        )
        if match:
            print(
                "note: samloader reported no value under 'Latest Stable Version'; "
                "using the newest previous stable version",
                file=sys.stderr,
            )
    if not match:
        # Plain `check-update` (no --all) prints the latest version alone.
        match = re.search(r"\b(" + FOUR_PART_VERSION + r")\b", text)
    if not match:
        raise ValueError(
            "no stable four-part firmware version found in samloader check-update output; "
            "supply the exact AP/CSC/CP/AP version with --version instead"
        )
    print(match.group(1))
    return 0


# Marketing names for models seen in the payloads repo, used to build the
# default feed display name when no --display-name is given.
MARKETING_NAMES = {
    "SM-A155N": "Galaxy A15",
    "SM-S156V": "Galaxy A15 5G",
    "SM-A366W": "Galaxy A36 5G",
    "SM-A566E": "Galaxy A56 5G",
    "SM-S721N": "Galaxy S24 FE",
    "SM-S921B": "Galaxy S25",
    "SM-S921N": "Galaxy S25",
    "SM-S926B": "Galaxy S25+",
    "SM-S928U": "Galaxy S24 Ultra",
    "SM-S928U1": "Galaxy S24 Ultra",
    "SM-S9180": "Galaxy S23 Ultra",
    "SM-S9380": "Galaxy S25 Ultra",
    "SM-S938N": "Galaxy S25 Ultra",
    "SM-S9370": "Galaxy S25 Edge",
    "SM-F966U": "Galaxy Z Fold 7",
    "SM-F966U1": "Galaxy Z Fold 7",
}

# Device props captured by `device-info`. Keys become the JSON `device`
# fields; values are the getprop names on Samsung builds.
DEVICE_PROP_KEYS = {
    "model": "ro.product.model",
    "product_name": "ro.product.name",
    "product_device": "ro.product.device",
    "product_board": "ro.product.board",
    "manufacturer": "ro.product.manufacturer",
    "brand": "ro.product.brand",
    "hardware": "ro.hardware",
    "platform": "ro.board.platform",
    "soc_manufacturer": "ro.soc.manufacturer",
    "soc_model": "ro.soc.model",
    "abi": "ro.product.cpu.abi",
    "android_release": "ro.build.version.release",
    "android_sdk": "ro.build.version.sdk",
    "oneui_version": "ro.build.version.oneui",
    "security_patch": "ro.build.version.security_patch",
    "bootloader": "ro.bootloader",
    "baseband": "ro.boot.baseband",
    "fingerprint": "ro.build.fingerprint",
    "boot_fingerprint": "ro.bootimage.build.fingerprint",
    "incremental": "ro.build.version.incremental",
    "csc_sales_code": "ro.csc.sales_code",
    "csc_multi": "ro.omc.multi_csc",
    "csc_country": "ro.csc.country_code",
    "csc_version": "ro.omc.build.version",
}


def run_adb(serial: str, args: list[str], timeout: int = 30) -> str:
    if shutil.which("adb") is None:
        raise RuntimeError("adb not found on PATH; install Android platform-tools")
    cmd = ["adb"] + (["-s", serial] if serial else []) + args
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"adb {' '.join(args[:2])} failed (rc={proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout


def parse_getprop(text: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\[([^\]]+)\]:\s*\[([^\]]*)\]", line)
        if match:
            props[match.group(1)] = match.group(2)
    return props


def build_four_part(ap: str, csc_version: str, cp: str | None = None) -> str | None:
    """Samsung four-part version: AP/CSC/CP/AP.

    The device exposes its own CSC firmware version (ro.omc.build.version,
    e.g. S156VTFNBDZDC), so the CSC part needs no guess. The CP part defaults
    to the AP part; pass --cp when the CP differs (some models ship a separate
    baseband build).
    """
    if not ap or not csc_version:
        return None
    cp = cp or ap
    return f"{ap}/{csc_version}/{cp}/{ap}"


def device_profile(product_device: str, ap: str) -> str | None:
    if product_device and ap:
        return f"{product_device}-{ap}"
    return None


def kernel_short(release: str) -> str | None:
    match = re.match(r"(\d+\.\d+\.\d+)", release or "")
    return match.group(1) if match else None


def samloader_check_update(model: str, region: str) -> str | None:
    if shutil.which("samloader") is None:
        raise RuntimeError("samloader not found on PATH; install samloader-rs")
    proc = subprocess.run(
        ["samloader", "check-update", "--model", model, "--region", region],
        capture_output=True,
        text=True,
        timeout=120,
    )
    match = re.search(FOUR_PART_VERSION, proc.stdout + proc.stderr)
    if not match:
        print(
            f"note: samloader check-update returned no version for {model}/{region} "
            f"(rc={proc.returncode})",
            file=sys.stderr,
        )
        return None
    return match.group(0)


def samloader_probe(model: str, region: str, version: str) -> bool:
    """Return True when Samsung FUS still serves the exact four-part version.

    A valid version makes samloader print the firmware version and start
    streaming; a retired build fails fast with an error. The download is
    killed by the timeout, so only a few hundred KB ever land in a temp dir.
    """
    if shutil.which("samloader") is None:
        raise RuntimeError("samloader not found on PATH; install samloader-rs")
    text = ""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "probe.zip"
        try:
            proc = subprocess.run(
                [
                    "samloader",
                    "download",
                    "--model",
                    model,
                    "--region",
                    region,
                    "--version",
                    version,
                    "--out-file",
                    str(out),
                ],
                capture_output=True,
                text=True,
                timeout=25,
            )
            text = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired as exc:
            # Timeout is the expected success path: streaming started.
            text = (exc.stdout or "") + (exc.stderr or "")
    return bool(re.search(r"Firmware Version:", text))


def cmd_device_info(args: argparse.Namespace) -> int:
    serial = args.serial
    if not serial:
        devices = [
            line.split()[0]
            for line in run_adb("", ["devices"]).splitlines()[1:]
            if line.strip() and line.split()[-1] == "device"
        ]
        if len(devices) != 1:
            raise ValueError(
                f"expected exactly one connected device, found {len(devices)}: {devices}; pass --serial"
            )
        serial = devices[0]

    props = parse_getprop(run_adb(serial, ["shell", "getprop"]))
    device: dict[str, object] = {}
    for key, prop in DEVICE_PROP_KEYS.items():
        device[key] = props.get(prop, "")
    device["page_size"] = int(
        run_adb(serial, ["shell", "getconf", "PAGE_SIZE"]).strip() or 0
    )
    device["kernel_release"] = run_adb(serial, ["shell", "uname", "-r"]).strip()
    device["kernel_version"] = kernel_short(str(device["kernel_release"])) or ""
    # pre-GKI kernels (e.g. Samsung 5.4) never ship BTF; probe the live kernel
    # so dispatch defaults match reality instead of always demanding BTF
    btf_probe = run_adb(serial, ["shell", "ls", "/sys/kernel/btf/vmlinux"]).strip()
    device["kernel_ships_btf"] = bool(btf_probe) and "No such file" not in btf_probe

    model = str(device["model"])
    region = str(device["csc_sales_code"])
    ap = str(device["incremental"])
    four_part = build_four_part(ap, str(device["csc_version"]), args.cp)

    firmware: dict[str, object] = {
        "model": model,
        "region": region,
        "device_build_4part": four_part,
    }
    if args.check_update:
        firmware["fus_latest_4part"] = samloader_check_update(model, region)
    if args.probe_fus and four_part:
        firmware["fus_serves_device_build"] = samloader_probe(model, region, four_part)

    profile = device_profile(str(device["product_device"]), ap)
    display_name = args.display_name or (
        f"{MARKETING_NAMES.get(model, f'Galaxy {model}')} | "
        f"Kernel {device['kernel_version']}"
        if device["kernel_version"]
        else MARKETING_NAMES.get(model, f"Galaxy {model}")
    )
    version = args.version or four_part or "latest"
    if four_part and firmware.get("fus_serves_device_build") is False:
        print(
            f"note: device build {four_part} is no longer served by FUS; "
            f"the dispatch falls back to 'latest' -- update the device first or pass --version",
            file=sys.stderr,
        )
        version = "latest"

    dispatch: dict[str, object] = {
        "profile": profile,
        "payload_id": profile,
        "model": model,
        "region": region,
        "version": version,
        "fingerprint": device["fingerprint"],
        "kernel_version": device["kernel_version"],
        "kernel_release": device["kernel_release"],
        "display_name": display_name,
        "source_target": args.source_target
        or "<set me: same kernel generation (e.g. dm3q for 5.15)>",
        "kernelsu_artifact": args.kernelsu_artifact
        or "<set me: reuse a ksud for this KMI or use kernelsu_build=ddk>",
        "probe_offset": args.probe_offset,
        "require_btf": bool(device["kernel_ships_btf"]),
    }

    info: dict[str, object] = {
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "adb_serial": serial,
        "device": device,
        "firmware": firmware,
        "dispatch": dispatch,
    }
    out_path = args.out or Path(f"device-info-{model}-{ap}.json")
    out_path.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out_path}")
    print_device_info_summary(info)
    return 0


def print_device_info_summary(info: dict[str, object]) -> None:
    d = info["device"]
    fw = info["firmware"]
    print("=" * 62)
    print(f"model          {d['model']}  (device {d['product_device']})")
    print(f"region/CSC     {d['csc_sales_code']}  (multi-CSC {d['csc_multi']})")
    print(
        f"android        {d['android_release']}  SDK {d['android_sdk']}  "
        f"One UI {d['oneui_version']}"
    )
    print(f"kernel         {d['kernel_release']}")
    print(f"soc            {d['soc_manufacturer']} {d['soc_model']}  pages {d['page_size']}")
    print(f"fingerprint    {d['fingerprint']}")
    if fw.get("device_build_4part"):
        print(f"firmware 4-part {fw['device_build_4part']}")
    if fw.get("fus_latest_4part"):
        print(f"FUS latest     {fw['fus_latest_4part']}")
    if fw.get("fus_serves_device_build") is not None:
        print(f"FUS serves dev build: {fw['fus_serves_device_build']}")
    print("-" * 62)
    print("workflow dispatch inputs:")
    for key, value in info["dispatch"].items():
        print(f"  {key:<16} {value}")


def cmd_extract_kernel(args: argparse.Namespace) -> int:
    args.workdir.mkdir(parents=True, exist_ok=True)
    ap_member = extract_ap_archive(args.firmware_zip, args.workdir)
    boot_lz4 = extract_from_tar(ap_member, "boot.img.lz4", args.workdir)
    boot = decompress_lz4(boot_lz4)
    boot_path = args.workdir / "boot.img"
    boot_path.write_bytes(boot)
    kernel_size = struct.unpack_from("<I", boot, 0x08)[0]
    kernel_payload = boot[0x1000 : 0x1000 + kernel_size]
    # Some Samsung kernels (Mediatek 5.10/5.15) ship the payload as gzip; the
    # stored `kernel` must be the raw ARM64 Image so BTF scans, the p0
    # fingerprint generator, and the banner scan all read real bytes instead
    # of compressed data.
    compressed = kernel_payload[:2] == b"\x1f\x8b"
    if compressed:
        kernel = gzip.decompress(kernel_payload)
        print(f"kernel payload is gzip-compressed ({len(kernel_payload)} bytes); "
              f"stored decompressed Image ({len(kernel)} bytes)")
    else:
        kernel = kernel_payload
    kernel_path = args.workdir / "kernel"
    kernel_path.write_bytes(kernel)
    print(f"boot.img sha256: {sha256_file(boot_path)}")
    print(f"kernel size: {len(kernel)}")
    print(f"kernel sha256: {sha256_file(kernel_path)}")
    release = kernel_release_from_image(kernel)
    if release:
        (args.workdir / "kernel-release.txt").write_text(release + "\n", encoding="utf-8")
        print(f"kernel release: {release}")
    return 0


def kernel_release_from_image(image: bytes) -> str | None:
    """Extract the uname release from the in-image 'Linux version ' banner.

    Some Samsung kernels embed other strings containing the marker before the
    real banner (observed on 5.15 images), so scan every occurrence and accept
    the first token that looks like a release (starts with MAJOR.MINOR.PATCH).
    """
    marker = b"Linux version "
    start = 0
    while True:
        start = image.find(marker, start)
        if start < 0:
            return None
        token = (
            image[start + len(marker) :]
            .split(b" ", 1)[0]
            .decode("ascii", errors="replace")
            .strip()
        )
        if re.match(r"^\d+\.\d+\.\d+", token):
            return token or None
        start += len(marker)


def extract_ap_archive(firmware_zip: Path, workdir: Path) -> Path:
    try:
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
    except zipfile.BadZipFile as exc:
        raise ValueError(
            f"{firmware_zip} is not a valid zip archive; "
            "samloader download --out-file writes a decrypted plain zip, "
            "but a raw .enc4 or direct-firmware-url download must be decrypted first"
        ) from exc


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


def load_raw_image(path: Path) -> bytes:
    """Read a kernel payload as a raw ARM64 Image.

    Some Samsung boot images (observed on Mediatek 5.10/5.15 kernels such as
    the A155N and a15x) store the kernel payload as a gzip stream. Every
    consumer of the raw Image (BTF scan, p0 fingerprint, banner scan) needs
    the decompressed bytes; vmlinux-to-elf handles this internally, so the
    nm-based offsets worked while the byte-level consumers silently read
    zlib data. Decompress here once so all callers agree.
    """
    data = path.read_bytes()
    if data[:2] == b"\x1f\x8b":
        return gzip.decompress(data)
    return data


def cmd_extract_btf(args: argparse.Namespace) -> int:
    image = load_raw_image(args.kernel)
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


def cmd_extract_fota(args: argparse.Namespace) -> int:
    """Read ro.build.* identity props from meta-data/fota.zip inside the firmware zip."""
    props: dict[str, str] = {}
    source = None
    try:
        with zipfile.ZipFile(args.firmware_zip) as archive:
            fota_names = [n for n in archive.namelist() if n.endswith("fota.zip")]
            if not fota_names:
                raise ValueError(f"no meta-data/fota.zip member in {args.firmware_zip}")
            fota_name = fota_names[0]
            with archive.open(fota_name) as src, zipfile.ZipFile(src) as fota:
                for member in fota.namelist():
                    if member.endswith("/"):
                        continue
                    text = fota.read(member).decode("utf-8", errors="replace")
                    for line in text.splitlines():
                        if "=" not in line:
                            continue
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip().strip('"')
                        if key.startswith("ro.") and key not in props:
                            props[key] = value
                            if source is None:
                                source = f"{fota_name}:{member}"
    except zipfile.BadZipFile as exc:
        raise ValueError(
            f"{args.firmware_zip} is not a valid zip archive; "
            "fota identity extraction needs the decrypted plain firmware zip"
        ) from exc
    if not props:
        raise ValueError(
            "no ro.* properties found in fota.zip; cannot derive BUILD_FINGERPRINT, "
            "supply the fingerprint via the target scaffold instead"
        )
    identity = {
        "fingerprint": props.get("ro.build.fingerprint", ""),
        "display_id": props.get("ro.build.display.id", ""),
        "model": props.get("ro.product.model", props.get("ro.product.device", "")),
        "sdk": props.get("ro.build.version.sdk", ""),
        "page_size": props.get("ro.product.cpu.abi", ""),
        "props_source": source or "",
        "props": props,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
    print(f"fota identity: fingerprint={identity['fingerprint'] or 'MISSING'}")
    print(f"fota identity: display_id={identity['display_id'] or 'MISSING'}")
    return 0


BTF_KIND_NAMES = {
    1: "INT",
    2: "PTR",
    3: "ARRAY",
    4: "STRUCT",
    5: "UNION",
    6: "ENUM",
    7: "FWD",
    8: "TYPEDEF",
    9: "VOLATILE",
    10: "CONST",
    11: "RESTRICT",
    12: "FUNC",
    13: "FUNC_PROTO",
    14: "VAR",
    15: "DATASEC",
    16: "FLOAT",
    17: "DECL_TAG",
    18: "TYPE_TAG",
    19: "ENUM64",
}


class BTFError(ValueError):
    pass


@dataclass
class BTFStruct:
    name: str
    kind: int
    size: int
    members: dict[str, int]  # member name -> byte offset (byte-aligned only)
    vlen: int


def parse_btf(data: bytes) -> tuple[bytes, list[BTFStruct]]:
    """Parse a raw little-endian BTF blob; return (string table, struct list).

    Only STRUCT/UNION types are returned. Member offsets that are not
    byte-aligned are skipped (the porting doc requires rejecting them).
    """
    if len(data) < 24:
        raise BTFError(f"BTF blob too short: {len(data)} bytes")
    magic, version, flags, header_len, type_off, type_len, str_off, str_len = struct.unpack_from(
        "<HBBIIIII", data, 0
    )
    if magic != 0xEB9F:
        raise BTFError(f"bad BTF magic 0x{magic:04x}")
    if version != 1:
        raise BTFError(f"unsupported BTF version {version}")
    if flags != 0:
        raise BTFError(f"unexpected BTF flags 0x{flags:x}")
    if header_len < 24:
        raise BTFError(f"BTF header too small: {header_len}")
    if header_len + type_off + type_len + str_len > len(data):
        raise BTFError("BTF sections exceed blob bounds")
    type_start = header_len + type_off
    type_end = type_start + type_len
    str_table = data[header_len + str_off : header_len + str_off + str_len]

    def string(name_off: int) -> str:
        if name_off >= len(str_table):
            return f"<bad-name-off {name_off}>"
        end = str_table.find(b"\x00", name_off)
        if end < 0:
            return ""
        return str_table[name_off:end].decode("utf-8", errors="replace")

    structs: list[BTFStruct] = []
    cursor = type_start
    while cursor < type_end:
        if cursor + 12 > type_end:
            raise BTFError("truncated BTF type record")
        name_off, info, size_or_type = struct.unpack_from("<III", data, cursor)
        cursor += 12
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        kind_flag = (info >> 31) & 1
        name = string(name_off)
        if kind in (4, 5):  # STRUCT / UNION
            size = size_or_type
            members: dict[str, int] = {}
            for _ in range(vlen):
                if cursor + 12 > type_end:
                    raise BTFError("truncated BTF struct member")
                m_name_off, m_type, m_offset = struct.unpack_from("<III", data, cursor)
                cursor += 12
                if kind_flag:
                    bit_offset = m_offset & 0xFFFFFF
                else:
                    bit_offset = m_offset
                m_name = string(m_name_off)
                if bit_offset & 7:
                    continue  # reject non-byte-aligned members, per porting doc
                members[m_name] = bit_offset >> 3
            structs.append(BTFStruct(name, kind, size, members, vlen))
        elif kind == 1:  # INT
            cursor += 4
        elif kind == 3:  # ARRAY
            cursor += 12
        elif kind == 6:  # ENUM
            cursor += vlen * 8
        elif kind == 13:  # FUNC_PROTO: vlen x btf_param { name_off, type } = 8 bytes each
            cursor += vlen * 8
        elif kind == 14:  # VAR
            cursor += 4
        elif kind == 15:  # DATASEC
            cursor += vlen * 12
        elif kind == 17:  # DECL_TAG
            cursor += 4
        elif kind == 19:  # ENUM64
            cursor += vlen * 12
        # PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT,
        # TYPE_TAG have no per-type payload after the 12-byte header.
    return str_table, structs


def cmd_btf_struct(args: argparse.Namespace) -> int:
    data = args.btf.read_bytes()
    try:
        _, structs = parse_btf(data)
    except BTFError as exc:
        raise ValueError(f"invalid raw BTF blob {args.btf}: {exc}") from exc
    by_name: dict[str, BTFStruct] = {}
    for s in structs:
        by_name.setdefault(s.name, s)
    wanted = [name.strip() for name in args.structs.split(",") if name.strip()]
    result: dict[str, dict] = {}
    missing: list[str] = []
    if "all" in wanted:
        wanted = list(by_name)
    for name in wanted:
        s = by_name.get(name)
        if s is None:
            missing.append(name)
            continue
        result[name] = {"kind": BTF_KIND_NAMES.get(s.kind, str(s.kind)), "size": s.size, "members": s.members}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"structs": result}, indent=2) + "\n", encoding="utf-8")
    for name in result:
        print(f"BTF {name}: size=0x{result[name]['size']:x} members={len(result[name]['members'])}")
    if missing:
        print(f"warning: structs not found in BTF: {', '.join(missing)}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# target.h derivation
# ---------------------------------------------------------------------------

# macro -> symbol name; offset = nm[symbol] - ELF base
SYMBOL_OFFSET_MACROS: dict[str, str] = {
    "ASHMEM_FOPS_OFF": "ashmem_fops",
    "ASHMEM_IOCTL_OFF": "ashmem_ioctl",
    "ASHMEM_COMPAT_IOCTL_OFF": "compat_ashmem_ioctl",
    "ASHMEM_MMAP_OFF": "ashmem_mmap",
    "ASHMEM_OPEN_OFF": "ashmem_open",
    "ASHMEM_RELEASE_OFF": "ashmem_release",
    "ASHMEM_SHOW_FDINFO_OFF": "ashmem_show_fdinfo",
    "CONFIGFS_READ_ITER_OFF": "configfs_read_iter",
    "CONFIGFS_BIN_WRITE_ITER_OFF": "configfs_bin_write_iter",
    "COPY_SPLICE_READ_OFF": "generic_file_splice_read",
    "NOOP_LLSEEK_OFF": "noop_llseek",
    "INIT_TASK_OFF": "init_task",
    "ROOT_TASK_GROUP_OFF": "root_task_group",
    "KMALLOC_CACHES_OFF": "kmalloc_caches",
    "ANON_PIPE_BUF_OPS_OFF": "anon_pipe_buf_ops",
    "CALL_USERMODEHELPER_EXEC_WORK_OFF": "call_usermodehelper_exec_work",
    "SYSTEM_UNBOUND_WQ_OFF": "system_unbound_wq",
    "SLIDE_NFULNL_LOGGER_OBJECT_OFF": "nfulnl_logger",
    "SLIDE_SYSCTL_BOOTID_OFF": "sysctl_bootid",
}

# Newer kernels renamed the splice read handler: on 6.6+ the fops->splice_read
# implementation is copy_splice_read (filemap_splice_read is a separate path).
# When the primary symbol is absent, fall back in order so derived values match
# the upstream per-kernel convention (generic on 6.1, copy on 6.6+).
SYMBOL_ALIASES: dict[str, tuple[str, ...]] = {
    "COPY_SPLICE_READ_OFF": ("copy_splice_read", "filemap_splice_read"),
    # pre-5.9 kernels (Samsung 5.4) name the configfs fops handlers
    # configfs_read_file/configfs_write_file and dispatch through the classic
    # read/write slots; the iter-based names only exist on 5.15+. The bin
    # variants match the exploit's binary-attribute fake buffer.
    "CONFIGFS_READ_ITER_OFF": ("configfs_read_bin_file", "configfs_read_file"),
    "CONFIGFS_BIN_WRITE_ITER_OFF": ("configfs_write_bin_file", "configfs_write_file"),
}

# legacy headers name the slide macros differently; when a template already
# defines the legacy name, a re-derivation must not append the new-style
# alias (it would carry the same value and create a spurious diff).
MACRO_NAME_EQUIVALENTS: dict[str, tuple[str, ...]] = {
    "SLIDE_NFULNL_LOGGER_NAME_OFF": ("SLIDE_NFULNL_LOGGER_OFF",),
    "SLIDE_NFULNL_LOGGER_OBJECT_OFF": ("SLIDE_LOGGERS_0_1_OFF",),
    "SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF": ("SLIDE_RANDOM_BOOT_ID_DATA_OFF",),
    "FAKE_TASK_USAGE_OFF": ("TASK_USAGE_OFF",),
    "FAKE_TASK_PRIO_OFF": ("TASK_PRIO_OFF",),
    "FAKE_TASK_NORMAL_PRIO_OFF": ("TASK_NORMAL_PRIO_OFF",),
    "FAKE_TASK_TASK_GROUP_OFF": ("TASK_SCHED_TASK_GROUP_OFF", "TASK_TASK_GROUP_OFF"),
    "FAKE_TASK_PI_LOCK_OFF": ("TASK_PI_LOCK_OFF",),
    "FAKE_TASK_PI_WAITERS_OFF": ("TASK_PI_WAITERS_OFF",),
    "FAKE_TASK_PI_TOP_TASK_OFF": ("TASK_PI_TOP_TASK_OFF",),
    "FAKE_TASK_PI_BLOCKED_ON_OFF": ("TASK_PI_BLOCKED_ON_OFF",),
}


def template_has_equivalent(text: str, macro: str) -> str | None:
    """Return the legacy macro name in the template that already carries the
    same value as `macro`, or None. Used to avoid appending duplicate
    new-style aliases when re-deriving legacy-style headers."""
    for equiv in MACRO_NAME_EQUIVALENTS.get(macro, ()):
        if re.search(rf"(?m)^\s*#define\s+{re.escape(equiv)}\b", text):
            return equiv
    return None


_CONST_RE = re.compile(r"0[xX][0-9a-fA-F]+|\d+")


def _eval_macro_rhs(text: str, rhs: str, _depth: int = 0) -> int | None:
    """Evaluate a #define right-hand side: a hex/decimal literal, a bare
    macro alias, or a simple (MACRO +/- const) expression. Returns None when
    the form is not understood (the caller then rewrites the definition)."""
    if _depth > 8:
        return None
    rhs = rhs.strip()
    if not rhs:
        return None
    # strip a C integer suffix and any trailing backslash
    rhs = re.sub(r"(ULL|ULLL|LL|L)$", "", rhs.strip().rstrip("\\"))
    const_pat = r"(0[xX][0-9a-fA-F]+|\d+)(?:ULL|LL|L)?"
    # (MACRO +/- const) and MACRO +/- const
    m = re.match(rf"^\(?\s*([A-Za-z_][A-Za-z0-9_]*)\s*([+-])\s*{const_pat}\s*\)?$", rhs)
    if m:
        name, op, const = m.group(1), m.group(2), m.group(3)
        base = _eval_macro_rhs(text, name, _depth + 1)
        if base is None:
            return None
        cval = int(const, 16) if const.lower().startswith("0x") else int(const)
        return base + cval if op == "+" else base - cval
    # const +/- MACRO (rare)
    m = re.match(rf"^\(?\s*{const_pat}\s*([+-])\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)?$", rhs)
    if m:
        const, op, name = m.group(1), m.group(2), m.group(3)
        base = _eval_macro_rhs(text, name, _depth + 1)
        if base is None:
            return None
        cval = int(const, 16) if const.lower().startswith("0x") else int(const)
        return cval + base if op == "+" else cval - base
    # bare macro alias
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", rhs):
        m = re.search(rf"(?m)^\s*#define\s+{re.escape(rhs)}\s+([^\n\\]+)", text)
        if m:
            return _eval_macro_rhs(text, m.group(1), _depth + 1)
        return None
    # plain literal
    if re.match(rf"^({_CONST_RE.pattern})$", rhs):
        return int(rhs, 16) if rhs.lower().startswith("0x") else int(rhs)
    return None


def macro_value_matches(text: str, macro: str, value: int) -> bool:
    """True when the template already defines `macro` with numeric value
    `value` (as a literal, alias, or simple expression). The definition is
    then left byte-identical instead of being flattened."""
    m = re.search(rf"(?m)^\s*#define\s+{re.escape(macro)}\s+([^\n\\]+)", text)
    if not m:
        return False
    return _eval_macro_rhs(text, m.group(1)) == value


def resolve_symbol(nm: dict[str, int], macro: str, symbol: str) -> tuple[str, int] | None:
    """Return (found_symbol, address) for a macro's symbol, trying aliases."""
    for candidate in (symbol,) + SYMBOL_ALIASES.get(macro, ()):
        addr = nm.get(candidate)
        if addr is not None:
            return candidate, addr
    return None


# composite offsets: symbol plus a BTF member offset within that object
COMPOSITE_SYMBOL_MACROS: dict[str, tuple[str, str, str]] = {
    # macro -> (symbol, struct, member); offset = nm[symbol] - base + member
    "ASHMEM_MISC_FOPS_OFF": ("ashmem_misc", "miscdevice", "fops"),
    "SELINUX_ENFORCING_OFF": ("selinux_state", "selinux_state", "enforcing"),
}

# BTF struct member -> target.h macro (task_struct members used by the fake task)
TASK_STRUCT_MACROS: dict[str, str] = {
    "usage": "FAKE_TASK_USAGE_OFF",
    "prio": "FAKE_TASK_PRIO_OFF",
    "normal_prio": "FAKE_TASK_NORMAL_PRIO_OFF",
    "sched_task_group": "FAKE_TASK_TASK_GROUP_OFF",
    "pi_lock": "FAKE_TASK_PI_LOCK_OFF",
    "pi_waiters": "FAKE_TASK_PI_WAITERS_OFF",
    "pi_top_task": "FAKE_TASK_PI_TOP_TASK_OFF",
    "pi_blocked_on": "FAKE_TASK_PI_BLOCKED_ON_OFF",
}

WORK_STRUCT_MACROS: dict[str, str] = {
    "data": "WORK_DATA_OFF",
    "entry": "WORK_ENTRY_OFF",
    "func": "WORK_FUNC_OFF",
}

PAGE_STRUCT_MACROS: dict[str, str] = {
    "compound_head": "STRUCT_PAGE_COMPOUND_HEAD_OFF",
    "slab_cache": "STRUCT_SLAB_CACHE_OFF",
    "page_type": "STRUCT_PAGE_TYPE_OFF",
}

FOPS_MACROS: dict[str, str] = {
    "owner": "FOPS_OWNER_OFF",
    "llseek": "FOPS_LLSEEK_OFF",
    "read": "FOPS_READ_OFF",
    "write": "FOPS_WRITE_OFF",
    "read_iter": "FOPS_READ_ITER_OFF",
    "write_iter": "FOPS_WRITE_ITER_OFF",
    "unlocked_ioctl": "FOPS_IOCTL_OFF",
    "compat_ioctl": "FOPS_COMPAT_IOCTL_OFF",
    "mmap": "FOPS_MMAP_OFF",
    "open": "FOPS_OPEN_OFF",
    "release": "FOPS_RELEASE_OFF",
    "splice_read": "FOPS_SPLICE_READ_OFF",
    "show_fdinfo": "FOPS_SHOW_FDINFO_OFF",
}

# best-effort groups: only applied when every member of the group is present
BEST_EFFORT_GROUPS: list[tuple[str, str, dict[str, str]]] = [
    ("workqueue_struct", "WQ_DFL_PWQ_OFF", {"dfl_pwq": "WQ_DFL_PWQ_OFF"}),
    (
        "pool_workqueue",
        "PWQ_POOL_OFF",
        {
            "pool": "PWQ_POOL_OFF",
            "wq": "PWQ_WQ_OFF",
            "work_color": "PWQ_WORK_COLOR_OFF",
            "refcnt": "PWQ_REFCNT_OFF",
            "nr_in_flight": "PWQ_NR_IN_FLIGHT_OFF",
            "nr_active": "PWQ_NR_ACTIVE_OFF",
            "max_active": "PWQ_MAX_ACTIVE_OFF",
        },
    ),
    ("worker_pool", "POOL_WORKLIST_OFF", {"worklist": "POOL_WORKLIST_OFF", "nr_idle": "POOL_NR_IDLE_OFF"}),
]

# configfs buffer offsets: derive from whichever struct actually carries
# needs_read_fill/bin_buffer members (struct configfs_buffer on 6.1/6.6).
CONFIGFS_BUFFER_MACROS: dict[str, str] = {
    "page": "CFG_PAGE_OFF",
    "needs_read_fill": "CFG_NEEDS_READ_FILL_OFF",
    "bin_buffer": "CFG_BIN_BUFFER_OFF",
    "bin_buffer_size": "CFG_BIN_BUFFER_SIZE_OFF",
    "cb_max_size": "CFG_CB_MAX_SIZE_OFF",
}

# macros that are never auto-derived; the report must list them explicitly so
# the scaffold provenance is complete (they come from the source target).
NEVER_DERIVED_MACROS: tuple[str, str, ...] = (
    ("P0_PAGE_OFFSET", "direct-map identity / page offset"),
    ("P0_PHYS_OFFSET", "physical load address (sboot disassembly)"),
    ("P0_KERNEL_PHYS_LOAD", "kernel physical load address (sboot disassembly)"),
    ("SLIDE_TRACEFS_EVENT_ID", "tracefs sched_blocked_reason event id"),
    ("SLIDE_PSELECT_WORD_SHIFT", "pselect6 fd-set qword layout"),
    ("SLIDE_NFULNL_LOGGER_NAME_OFF", "nfnetlink_log name string target"),
    ("SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF", "random_table[] boot_id data pointer"),
    ("LOCK_OFF", "fake-task page layout"),
    ("W0_OFF", "fake-task page layout"),
    ("FOPS_OFF", "fake-task page layout"),
    ("SCRATCH_OFF", "fake-task page layout"),
    ("RIGHT_OFF", "fake-task page layout"),
    ("LEFT_OFF", "fake-task page layout"),
    ("FAKE_TASK_OFF", "fake-task page layout"),
    ("FAKE_WAITER_TREE_PRIO_OFF", "fake waiter layout"),
    ("FAKE_WAITER_TREE_DEADLINE_OFF", "fake waiter layout"),
    ("FAKE_WAITER_PI_TREE_ENTRY_OFF", "fake waiter layout"),
    ("FAKE_WAITER_PI_TREE_PRIO_OFF", "fake waiter layout"),
    ("FAKE_WAITER_PI_TREE_DEADLINE_OFF", "fake waiter layout"),
    ("FAKE_WAITER_TASK_OFF", "fake waiter layout"),
    ("FAKE_WAITER_LOCK_OFF", "fake waiter layout"),
    ("FAKE_WAITER_WAKE_STATE_OFF", "fake waiter layout"),
    ("FAKE_WAITER_WW_CTX_OFF", "fake waiter layout"),
)


def elf_load_base(path: Path) -> int | None:
    """Recovered vmlinux base = lowest PT_LOAD p_vaddr (vmlinux-to-elf sets it)."""
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        with path.open("rb") as fh:
            elf = ELFFile(fh)
            bases = [seg["p_vaddr"] for seg in elf.iter_segments() if seg["p_type"] == "PT_LOAD"]
            return min(bases) if bases else None
    except Exception:  # noqa: BLE001
        return None


def replace_define(text: str, macro: str, value: str) -> str:
    """Replace every '#define <macro> ...' logical line (handles backslash continuations)."""
    out_lines: list[str] = []
    lines = text.split("\n")
    i = 0
    replaced = False
    while i < len(lines):
        line = lines[i]
        m = re.match(rf"^(\s*#define\s+{re.escape(macro)}\s+)(.*)$", line)
        if not m:
            out_lines.append(line)
            i += 1
            continue
        replaced = True
        # consume continuation lines: a line continues while the previous
        # emitted line ended with a backslash
        cont_lines: list[str] = []
        continues = m.group(2).rstrip().endswith("\\")
        i += 1
        while continues and i < len(lines):
            cont_lines.append(lines[i])
            continues = lines[i].rstrip().endswith("\\")
            i += 1
        if cont_lines:
            # keep the multi-line backslash layout so a re-derivation of an
            # existing header stays byte-compatible with the committed file
            indent = re.match(r"^(\s*)", cont_lines[0]).group(1) or "  "
            out_lines.append(m.group(1).rstrip() + " \\")
            out_lines.append(indent + value)
        else:
            out_lines.append(m.group(1) + value)
        continue
    if not replaced:
        raise ValueError(f"template target.h has no #define {macro}")
    return "\n".join(out_lines)


def add_define_before_endif(text: str, macro: str, value: str) -> str:
    if re.search(rf"(?m)^\s*#define\s+{re.escape(macro)}\b", text):
        return replace_define(text, macro, value)
    lines = text.split("\n")
    for idx in range(len(lines) - 1, -1, -1):
        if re.match(r"^\s*#endif", lines[idx]):
            lines.insert(idx, f"#define {macro} {value}")
            return "\n".join(lines)
    raise ValueError(f"cannot append {macro}: template target.h has no #endif")


def set_define(text: str, macro: str, value: str) -> str:
    """Replace the macro if the template has it, otherwise append it before #endif."""
    if re.search(rf"(?m)^\s*#define\s+{re.escape(macro)}\b", text):
        return replace_define(text, macro, value)
    return add_define_before_endif(text, macro, value)


def fmt_like(text: str, macro: str, value: int) -> str:
    """Render a derived number using the template's existing literal style.

    The repo's committed headers are not uniform: large symbol offsets are
    8-digit padded hex with a ULL suffix (0x013d9d48ULL), small struct member
    offsets are unpadded hex without a suffix (FOPS_OWNER_OFF 0x00), and the
    configfs buffer offsets are decimal (CFG_PAGE_OFF 16). Matching the
    template's style keeps derived headers byte-compatible with the scaffold
    so a re-derivation of an existing target produces no cosmetic diff.
    """
    m = re.search(rf"(?m)^\s*#define\s+{re.escape(macro)}\s+([^\s\\]+)", text)
    if m:
        tok = m.group(1)
        hm = re.match(r"0[xX]([0-9a-fA-F]+)(ULL|LL|L)?$", tok)
        if hm:
            width = max(len(hm.group(1)), 1)
            return f"0x{value:0{width}x}{hm.group(2) or ''}"
        dm = re.match(r"[+-]?\d+(ULL|LL|L)?$", tok)
        if dm:
            return f"{value}{dm.group(1) or ''}"
    # macro missing from the template (append path) or unknown literal style:
    # repo convention is 8-digit padded hex with ULL
    return f"0x{value:08x}ULL"


def set_define_num(text: str, macro: str, value: int) -> str:
    return set_define(text, macro, fmt_like(text, macro, value))


def cmd_gen_target_h(args: argparse.Namespace) -> int:
    text = args.template.read_text(encoding="utf-8", errors="replace")
    # read_text normalizes line endings, so detect EOL from the raw bytes
    template_crlf = b"\r\n" in args.template.read_bytes()
    report: list[str] = [f"# target.h derivation report for {args.profile}", ""]

    def derived(label: str) -> None:
        report.append(f"- [DERIVED] {label}")

    def scaffolded(macro: str, reason: str) -> None:
        report.append(f"- [SCAFFOLD] {macro} kept from template ({reason})")

    def set_derived(macro: str, value: int, source: str) -> None:
        """Write a derived value unless the template already carries it.

        Two "already correct" cases are left byte-identical so re-derivation
        of an existing header produces no spurious diff: (1) the value lives
        under a legacy macro name, (2) the macro itself is defined as a
        literal, alias, or simple expression with the same numeric value
        (a36xq-style headers).
        """
        nonlocal text
        equiv = template_has_equivalent(text, macro)
        if equiv is not None:
            report.append(
                f"- [INFO] {macro} = 0x{value:x} ({source}) "
                f"not emitted: template defines equivalent {equiv}"
            )
            return
        if macro_value_matches(text, macro, value):
            report.append(f"- [INFO] {macro} = 0x{value:x} ({source}) already correct in template; kept as-is")
            return
        text = set_define_num(text, macro, value)
        derived(f"{macro} = 0x{value:x} ({source})")

    # --- ELF base ---------------------------------------------------------
    base: int | None = None
    if args.elf_base:
        base = parse_int(args.elf_base)
    elif args.vmlinux_elf:
        base = elf_load_base(args.vmlinux_elf)
    if base is None:
        base = parse_macro_int(text, "KIMAGE_TEXT_BASE")
        if base is not None:
            scaffolded("KIMAGE_TEXT_BASE", "no recovered ELF supplied; template value used")
    else:
        text = set_define_num(text, "KIMAGE_TEXT_BASE", base)
        derived(f"KIMAGE_TEXT_BASE = 0x{base:x} (recovered ELF PT_LOAD base)")

    # --- firmware identity ------------------------------------------------
    fingerprint: str | None = None
    if args.fota_props and args.fota_props.exists():
        props = json.loads(args.fota_props.read_text(encoding="utf-8"))
        fingerprint = props.get("fingerprint") or None
        if fingerprint:
            text = set_define(text, "BUILD_FINGERPRINT", f'"{fingerprint}"')
            derived(f"BUILD_FINGERPRINT = {fingerprint} (fota.zip ro.build.fingerprint)")
        else:
            scaffolded("BUILD_FINGERPRINT", "fota.zip had no ro.build.fingerprint")
        if props.get("display_id"):
            report.append(f"- [INFO] ro.build.display.id = {props['display_id']}")
    if not fingerprint and args.fingerprint:
        fingerprint = args.fingerprint
        text = set_define(text, "BUILD_FINGERPRINT", f'"{fingerprint}"')
        derived(f"BUILD_FINGERPRINT = {fingerprint} (--fingerprint input)")
    if not fingerprint:
        # keep the scaffold value but flatten it so downstream gates can parse it
        template_match = re.search(r'#define\s+BUILD_FINGERPRINT\s+[\s\\]*"([^"]+)"', text)
        if template_match:
            text = set_define(text, "BUILD_FINGERPRINT", f'"{template_match.group(1)}"')
            scaffolded("BUILD_FINGERPRINT", "no fota.zip and no --fingerprint; template value flattened and kept")
        else:
            scaffolded("BUILD_FINGERPRINT", "no fota.zip and no --fingerprint; template has no fingerprint either")

    # Each variant label is a distinct string; replace by content, not by macro
    # name (replace_define would clobber both branches with the same label).
    for suffix in ("app-physical-p0-oracle", "root-umh"):
        new_label = f'"{args.profile}-{suffix}"'
        text, replaced = re.subn(rf'"[^"]*-{re.escape(suffix)}"', new_label, text, count=1)
        if replaced:
            derived(f"BUILD_VARIANT_LABEL ({suffix.split('-')[0]}) = {args.profile}-{suffix}")
        else:
            scaffolded(f"BUILD_VARIANT_LABEL {suffix}", "template does not use this label suffix")

    p0_include = f'targets/{args.profile}/p0_fingerprint.h'
    text = set_define(text, "P0_FINGERPRINT_HEADER", f'"{p0_include}"')
    derived(f"P0_FINGERPRINT_HEADER = {p0_include}")

    # --- symbol offsets from recovered vmlinux -----------------------------
    nm: dict[str, int] = {}
    if args.vmlinux_nm and args.vmlinux_nm.exists():
        nm = parse_nm(args.vmlinux_nm)
        if len(nm) < 1000:
            report.append(f"- [WARN] vmlinux nm dump has only {len(nm)} symbols")
    else:
        report.append("- [WARN] no vmlinux nm dump supplied; symbol offsets are NOT derived")
    if base is not None and nm:
        configfs_iter_api = 1
        for macro, symbol in SYMBOL_OFFSET_MACROS.items():
            resolved = resolve_symbol(nm, macro, symbol)
            if resolved is None:
                scaffolded(macro, f"symbol {symbol} not in recovered vmlinux")
                continue
            found_symbol, addr = resolved
            offset = addr - base
            set_derived(macro, offset, f"nm {found_symbol} - base")
            if macro == "CONFIGFS_READ_ITER_OFF" and found_symbol != "configfs_read_iter":
                # classic file-based configfs fops: payload must install the
                # handlers in the read/write slots instead of read_iter/write_iter
                configfs_iter_api = 0
        # tell the payload which file_operations slots the configfs handlers
        # live in: 1 = read_iter/write_iter (5.15+), 0 = read/write (5.4).
        # Only emitted for pre-iter kernels so re-deriving an existing 5.10+
        # header keeps it byte-identical (the payload defaults to iter slots).
        if re.search(r"(?m)^\s*#define\s+CONFIGFS_ITER_API\b", text):
            text = re.sub(
                r"(?m)^\s*#define\s+CONFIGFS_ITER_API\s+\d+.*",
                f"#define CONFIGFS_ITER_API {configfs_iter_api}",
                text,
            )
            derived(f"CONFIGFS_ITER_API = {configfs_iter_api}")
        elif configfs_iter_api == 0:
            text = set_define(text, "CONFIGFS_ITER_API", 0)
            derived("CONFIGFS_ITER_API = 0 (classic configfs read/write fops)")
        for macro, (symbol, struct_name, member) in COMPOSITE_SYMBOL_MACROS.items():
            addr = nm.get(symbol)
            member_off = struct_member_offset(args.struct_offsets, struct_name, member)
            if addr is None or member_off is None:
                scaffolded(macro, f"need nm[{symbol}] and BTF {struct_name}.{member}")
                continue
            offset = addr - base + member_off
            set_derived(macro, offset, f"nm {symbol} + BTF {struct_name}.{member}")

    # --- struct offsets from raw BTF ---------------------------------------
    if args.struct_offsets and args.struct_offsets.exists():
        btf = json.loads(args.struct_offsets.read_text(encoding="utf-8"))
        structs = btf.get("structs", {})
        task = structs.get("task_struct", {}).get("members", {})
        for member, macro in TASK_STRUCT_MACROS.items():
            offset = task.get(member)
            if offset is None:
                scaffolded(macro, f"BTF task_struct.{member} missing")
                continue
            set_derived(macro, offset, f"BTF task_struct.{member}")
        work = structs.get("work_struct", {}).get("members", {})
        for member, macro in WORK_STRUCT_MACROS.items():
            offset = work.get(member)
            if offset is None:
                scaffolded(macro, f"BTF work_struct.{member} missing")
                continue
            set_derived(macro, offset, f"BTF work_struct.{member}")
        page = structs.get("page", {})
        page_members = page.get("members", {})
        for member, macro in PAGE_STRUCT_MACROS.items():
            offset = page_members.get(member)
            if offset is None:
                scaffolded(macro, f"BTF page.{member} missing")
                continue
            set_derived(macro, offset, f"BTF page.{member}")
        if page.get("size"):
            set_derived("STRUCT_PAGE_SIZE", page['size'], "BTF sizeof(struct page)")
        fops = structs.get("file_operations", {})
        fops_members = fops.get("members", {})
        for member, macro in FOPS_MACROS.items():
            offset = fops_members.get(member)
            if offset is None:
                scaffolded(macro, f"BTF file_operations.{member} missing")
                continue
            set_derived(macro, offset, f"BTF file_operations.{member}")
        if fops.get("size") and re.search(rf"(?m)^\s*#define\s+SIZEOF_FILE_OPERATIONS\b", text):
            set_derived("SIZEOF_FILE_OPERATIONS", fops['size'], "BTF sizeof(struct file_operations)")
        elif fops.get("size"):
            report.append(
                "- [INFO] SIZEOF_FILE_OPERATIONS not emitted: template does not define it, "
                "and FOPS_SHOW_FDINFO_OFF satisfies the size gate"
            )

        # best-effort groups
        for struct_name, first_macro, members in BEST_EFFORT_GROUPS:
            s = structs.get(struct_name, {}).get("members", {})
            if all(member in s for member in members):
                for member, macro in members.items():
                    set_derived(macro, s[member], f"BTF {struct_name}.{member}")
            else:
                scaffolded(first_macro, f"BTF {struct_name} missing members")

        cfg_candidates = [
            (sname, s.get("members", {}))
            for sname, s in structs.items()
            if "needs_read_fill" in s.get("members", {}) and "bin_buffer" in s.get("members", {})
        ]
        if cfg_candidates:
            sname, members = cfg_candidates[0]
            if all(member in members for member in CONFIGFS_BUFFER_MACROS):
                for member, macro in CONFIGFS_BUFFER_MACROS.items():
                    set_derived(macro, members[member], f"BTF {sname}.{member}")
            else:
                scaffolded("CFG_PAGE_OFF", f"BTF {sname} missing configfs buffer members")
        else:
            scaffolded("CFG_PAGE_OFF", "no configfs buffer struct in BTF")
    else:
        scaffolded("FAKE_TASK_USAGE_OFF", "no BTF struct offsets supplied")
        scaffolded("STRUCT_PAGE_SIZE", "no BTF struct offsets supplied")
        scaffolded("SIZEOF_FILE_OPERATIONS", "no BTF struct offsets supplied")

    # --- worker caller offset from objdump (best-effort) --------------------
    if args.worker_objdump and args.worker_objdump.exists() and base is not None:
        call_sites = find_worker_schedule_call_sites(args.worker_objdump.read_text(encoding="utf-8", errors="replace"))
        if len(call_sites) == 1:
            caller = call_sites[0] - base
            set_derived("SLIDE_TRACEFS_WORKER_CALLER_OFF", caller, "next instr after bl schedule in worker_thread")
        elif len(call_sites) > 1:
            report.append(
                f"- [WARN] {len(call_sites)} 'bl schedule' sites in worker_thread; "
                "SLIDE_TRACEFS_WORKER_CALLER_OFF kept from template"
            )
        else:
            scaffolded("SLIDE_TRACEFS_WORKER_CALLER_OFF", "no 'bl schedule' site found in worker_thread objdump")

    # list every macro the derivation never attempts, so the scaffold
    # provenance is complete even when the value was left untouched
    for macro, why in NEVER_DERIVED_MACROS:
        if re.search(rf"(?m)^\s*#define\s+{re.escape(macro)}\b", text):
            report.append(f"- [SCAFFOLD] {macro} kept from template ({why})")

    args.target_dir.mkdir(parents=True, exist_ok=True)
    out = args.target_dir / "target.h"
    # keep the template's line endings so a re-derivation of an existing header
    # produces no whole-file EOL diff against the committed CRLF files
    out_text = text.replace("\n", "\r\n") if template_crlf else text
    out.write_text(out_text, encoding="utf-8", newline="")
    report_path = args.report or (args.target_dir / "port-report.md")
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")
    derived_count = sum(1 for line in report if line.startswith("- [DERIVED]"))
    scaffold_count = sum(1 for line in report if line.startswith("- [SCAFFOLD]"))
    print(f"wrote {out} (derived={derived_count}, scaffolded={scaffold_count})")
    print(f"wrote {report_path}")
    return 0


def struct_member_offset(struct_offsets: Path | None, struct_name: str, member: str) -> int | None:
    if not struct_offsets or not struct_offsets.exists():
        return None
    try:
        data = json.loads(struct_offsets.read_text(encoding="utf-8"))
        return data.get("structs", {}).get(struct_name, {}).get("members", {}).get(member)
    except (json.JSONDecodeError, OSError):
        return None


def find_worker_schedule_call_sites(objdump: str) -> list[int]:
    """Return absolute addresses of the instruction after every 'bl schedule' in worker_thread."""
    sites: list[int] = []
    lines = objdump.splitlines()
    for idx, line in enumerate(lines):
        if "\tbl\t" not in line and " bl " not in line:
            continue
        operand = line.split("\t", 2)[-1] if "\t" in line else line
        if "schedule" not in operand:
            continue
        addr_match = re.match(r"\s*([0-9a-fA-F]+):", line)
        if not addr_match or idx + 1 >= len(lines):
            continue
        next_line = lines[idx + 1]
        next_addr = re.match(r"\s*([0-9a-fA-F]+):", next_line)
        if not next_addr:
            continue
        sites.append(int(next_addr.group(1), 16))
    return sites


def cmd_gen_p0(args: argparse.Namespace) -> int:
    probe_offset = parse_int(args.probe_offset)
    image = load_raw_image(args.kernel)
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
    # Byte-compatible with the committed p0_fingerprint.h layout: generator
    # comments, offsets on one line, two qwords per row line with a 4-space
    # continuation. (scaffold-target strips the comments when replacing a
    # comment-less committed file such as pa3q's.)
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
        w = [f"0x{x:016x}ULL" for x in words]
        lines.append(f"  {{ 0x{slide:06x}ULL, {{ {w[0]}, {w[1]},")
        lines.append(f"    {w[2]}, {w[3]},")
        lines.append(f"    {w[4]}, {w[5]},")
        lines.append(f"    {w[6]}, {w[7]} }} }},")
    lines.extend(["};", "", "#endif", ""])
    return "\n".join(lines)


def cmd_scaffold_target(args: argparse.Namespace) -> int:
    targets = args.payloads_repo / "src" / "targets"
    src = targets / args.source_target
    dst = targets / args.profile
    if not src.exists():
        raise ValueError(f"source target does not exist: {src}")
    backup = targets / f"{args.profile}.source-backup"
    if dst.exists():
        if not args.replace_existing:
            raise ValueError(f"target already exists: {dst}")
        if backup.exists():
            shutil.rmtree(backup)
        # Always preserve the profile's own committed files before scaffolding
        # over them, not just when source_target == profile. Never-derived
        # macros (SLIDE_NFULNL_LOGGER_NAME_OFF, SLIDE_TRACEFS_EVENT_ID, ...)
        # carry device-tested values; gen-target-h selects this backup as its
        # template, so a re-port with a foreign source_target must not clobber
        # them with the source target's values.
        shutil.copytree(dst, backup)
    # A re-port scaffolds from the profile's own committed files (never-derived
    # values stay put); a genuinely new profile scaffolds from the source target.
    basis = backup if backup.exists() else src
    if dst.exists():
        shutil.rmtree(dst)
    if basis != src:
        print(f"note: {args.profile} already exists; scaffolding from its own committed files, ignoring source_target {args.source_target}")
    shutil.copytree(basis, dst)
    if args.skip_target_header:
        (dst / "target.h").unlink(missing_ok=True)
        print("note: target.h not copied (--skip-target-header); run gen-target-h to derive it")
    if args.p0_header:
        p0_out = dst / "p0_fingerprint.h"
        p0_text = Path(args.p0_header).read_text(encoding="utf-8", errors="replace")
        # match the existing committed file's style (CRLF line endings and the
        # leading generator comment block) so a re-derivation is byte-identical
        old_p0 = p0_out.read_bytes() if p0_out.exists() else b""
        if b"\r\n" in old_p0:
            p0_text = p0_text.replace("\n", "\r\n")
        if old_p0 and b"// Generated from the exact raw Image." not in old_p0:
            lines = p0_text.split("\n")
            while lines and lines[0].startswith("// Generated from the exact raw Image."):
                lines.pop(0)
                if lines and lines[0].startswith("// Each row maps actual slide"):
                    lines.pop(0)
                if lines and lines[0].strip() == "":
                    lines.pop(0)
            p0_text = "\n".join(lines)
        p0_out.write_text(p0_text, encoding="utf-8", newline="")
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
        "## Porting Status\n\n"
        "Mechanically derived constants (fingerprint, symbol offsets, BTF struct "
        "offsets) were computed from this exact firmware; see "
        "`src/targets/<profile>/port-report.md` for the full derived vs scaffolded "
        "breakdown.\n\n"
        "## Required Manual Review\n\n"
        "- Verify scaffolded constants listed in `port-report.md`: physical load "
        "addresses, tracefs event ID, pselect word shift, fake-task/waiter layout, "
        "and any offset the recovery could not derive.\n"
        "- Build and audit the exact KernelSU module and late-load binary (or "
        "document reuse of a same-KMI artifact).\n"
        "- Run hardware validation on an owned or explicitly authorized device.\n",
        encoding="utf-8",
    )
    print(f"wrote {doc}")
    return 0


def payloads_owner(repo: Path) -> str:
    """Return the GitHub owner of the payloads repo checkout (e.g. 'BuSung-dev')
    so feed artifact URLs point at the repo the PR actually targets. Falls back to
    the upstream owner when the checkout has no usable remote."""
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "remote"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.split()
    except (subprocess.SubprocessError, OSError):
        out = []
    owners = []
    for remote in out or ["origin"]:
        try:
            url = subprocess.run(
                ["git", "-C", str(repo), "remote", "get-url", remote],
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
        except (subprocess.SubprocessError, OSError):
            continue
        match = re.search(r"github\.com[:/]([^/]+)/Root-My-Galaxy-Payloads(?:\.git)?$", url)
        if match:
            owners.append(match.group(1))
    # In CI the fork is the only remote ('origin'). In a local checkout the
    # fork may be a named remote alongside upstream; prefer the fork over
    # upstream so URLs point at the repo the PR targets.
    for owner in owners:
        if owner != "BuSung-dev":
            return owner
    return owners[0] if owners else "BuSung-dev"


def cmd_add_feed_entry(args: argparse.Namespace) -> int:
    repo = args.payloads_repo
    payload_id = args.payload_id or args.profile
    feed_path = repo / "support" / "targets-v3.json"
    original = feed_path.read_text(encoding="utf-8")
    feed_crlf = b"\r\n" in feed_path.read_bytes()
    data = json.loads(original)
    existing_entries = [p for p in data.get("payloads", []) if p.get("payloadId") == payload_id]
    existing = existing_entries[0] if existing_entries else {}
    exploit_rel = args.exploit_path.resolve().relative_to(repo.resolve()).as_posix()
    raw_prefix = f"https://raw.githubusercontent.com/{payloads_owner(repo)}/Root-My-Galaxy-Payloads/main/"
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
            "url": f"{raw_prefix}{exploit_rel}",
            "size": args.exploit_path.stat().st_size,
        },
    }
    # KernelSU is optional: pre-GKI kernels (e.g. Samsung 5.4) cannot run
    # ksud at all, so a port can legitimately ship without a kernelsu entry.
    if args.kernelsu_path and args.kernelsu_path.exists():
        kernelsu_rel = args.kernelsu_path.resolve().relative_to(repo.resolve()).as_posix()
        entry["kernelsu"] = {
            "url": f"{raw_prefix}{kernelsu_rel}",
            "size": args.kernelsu_path.stat().st_size,
        }
    if args.preserve_existing_metadata and "requiresFreshP0Session" in existing:
        entry["requiresFreshP0Session"] = existing["requiresFreshP0Session"]
    elif args.requires_fresh_p0_session:
        entry["requiresFreshP0Session"] = True
    # work in LF-normalized text (read_text already normalized), then restore
    # the file's original line endings at write time so a no-op update is
    # byte-for-byte identical
    span = find_payload_span(original, payload_id)
    if span is not None and span[2] == entry:
        # the entry is semantically unchanged: keep its exact original text so
        # a re-port of an existing payload produces no feed diff at all
        new_text = original
    elif span is not None:
        start, end, _old = span
        new_text = original[:start] + serialize_payload_entry(entry) + original[end:]
    else:
        arr_close = original.rfind("]")
        new_text = (
            original[:arr_close]
            + ",\n"
            + serialize_payload_entry(entry)
            + "\n"
            + original[arr_close:]
        )
    if feed_crlf:
        new_text = new_text.replace("\n", "\r\n")
    feed_path.write_text(new_text, encoding="utf-8", newline="")
    print(f"updated {feed_path}")
    return 0


def find_payload_span(text: str, payload_id: str) -> tuple[int, int, dict] | None:
    """Locate the exact text span (start, end, parsed obj) of a payload entry."""
    dec = json.JSONDecoder()
    try:
        key = text.index('"payloads"')
        arr = text.index("[", key)
    except ValueError:
        return None
    idx = arr + 1
    while True:
        while idx < len(text) and text[idx] in " \t\r\n":
            idx += 1
        if idx >= len(text) or text[idx] == "]":
            return None
        try:
            obj, end = dec.raw_decode(text, idx)
        except json.JSONDecodeError:
            return None
        if obj.get("payloadId") == payload_id:
            # stop at the object close: the trailing comma (if any) stays in
            # original[end:] so a span replacement keeps it. Back the start up
            # to the beginning of the line so the serializer's own indent is
            # not stacked on top of the file's existing indentation.
            start = idx
            while start > 0 and text[start - 1] in " \t":
                start -= 1
            return start, end, obj
        idx = end
        while idx < len(text) and text[idx] in " \t\r\n,":
            idx += 1


def serialize_payload_entry(entry: dict, eol: str = "\n") -> str:
    """Render one payload entry in the upstream feed style: 6-space fields,
    short arrays (<=2 items) inline, longer arrays and objects multi-line."""
    field = "      "
    sub = "        "
    lines = ["    {"]
    keys = list(entry.keys())
    for i, k in enumerate(keys):
        comma = "," if i < len(keys) - 1 else ""
        v = entry[k]
        if isinstance(v, dict):
            lines.append(f'{field}"{k}": {{')
            sk = list(v.keys())
            for j, s in enumerate(sk):
                sc = "," if j < len(sk) - 1 else ""
                lines.append(f'{sub}"{s}": {json.dumps(v[s])}{sc}')
            lines.append(f"{field}}}{comma}")
        elif isinstance(v, list) and len(v) <= 2:
            lines.append(f'{field}"{k}": {json.dumps(v)}{comma}')
        elif isinstance(v, list):
            lines.append(f'{field}"{k}": [')
            for j, item in enumerate(v):
                ic = "," if j < len(v) - 1 else ""
                lines.append(f"{sub}{json.dumps(item)}{ic}")
            lines.append(f"{field}]{comma}")
        else:
            lines.append(f'{field}"{k}": {json.dumps(v)}{comma}')
    lines.append("    }")
    return eol.join(lines)


def cmd_validate_feed(args: argparse.Namespace) -> int:
    feed_path = args.payloads_repo / "support" / "targets-v3.json"
    data = json.loads(feed_path.read_text(encoding="utf-8"))
    if data.get("schemaVersion") != 3:
        raise ValueError("schemaVersion must be 3")
    errors = 0
    for payload in data.get("payloads", []):
        for field in ("exploit", "kernelsu"):
            if field not in payload:
                continue  # kernelsu is optional (pre-GKI ports ship without it)
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
    required_target_macros = [
        "BUILD_FINGERPRINT",
        "KIMAGE_TEXT_BASE",
        "P0_PAGE_OFFSET",
        "P0_PHYS_OFFSET",
        "P0_KERNEL_PHYS_LOAD",
        "SLIDE_TRACEFS_WORKER_CALLER_OFF",
        "P0_FINGERPRINT_HEADER",
        "ASHMEM_FOPS_OFF",
        "ASHMEM_IOCTL_OFF",
        "CONFIGFS_READ_ITER_OFF",
        "COPY_SPLICE_READ_OFF",
        "NOOP_LLSEEK_OFF",
        "INIT_TASK_OFF",
        "ROOT_TASK_GROUP_OFF",
        "SELINUX_ENFORCING_OFF",
        "KMALLOC_CACHES_OFF",
        "ANON_PIPE_BUF_OPS_OFF",
        "CALL_USERMODEHELPER_EXEC_WORK_OFF",
        "SYSTEM_UNBOUND_WQ_OFF",
        "SLIDE_SYSCTL_BOOTID_OFF",
        "FAKE_WAITER_TASK_OFF",
        "WORK_FUNC_OFF",
    ]
    required_macro_groups = [
        # legacy headers name these differently (SLIDE_NFULNL_LOGGER_OFF,
        # SLIDE_LOGGERS_0_1_OFF, SLIDE_RANDOM_BOOT_ID_DATA_OFF)
        ("nfnetlink logger name", ["SLIDE_NFULNL_LOGGER_NAME_OFF", "SLIDE_NFULNL_LOGGER_OFF"]),
        ("nfnetlink logger object", ["SLIDE_NFULNL_LOGGER_OBJECT_OFF", "SLIDE_LOGGERS_0_1_OFF"]),
        ("random boot_id data ptr", ["SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF", "SLIDE_RANDOM_BOOT_ID_DATA_OFF"]),
        ("file_operations size", ["SIZEOF_FILE_OPERATIONS", "FOPS_SHOW_FDINFO_OFF"]),
        ("task usage offset", ["TASK_USAGE_OFF", "FAKE_TASK_USAGE_OFF"]),
        ("task pi_lock offset", ["TASK_PI_LOCK_OFF", "FAKE_TASK_PI_LOCK_OFF"]),
        ("task pi_waiters offset", ["TASK_PI_WAITERS_OFF", "FAKE_TASK_PI_WAITERS_OFF"]),
        ("page size", ["SIZEOF_PAGE", "STRUCT_PAGE_SIZE"]),
    ]

    errors: list[str] = []
    if not target_h.exists():
        errors.append(f"missing target header: {target_h}")
    if not p0_h.exists():
        errors.append(f"missing P0 fingerprint: {p0_h}")
    if not artifact.exists():
        errors.append(f"missing release payload: {artifact}")
    elif artifact.stat().st_size > args.release_size_max:
        errors.append(
            f"release payload is {artifact.stat().st_size} bytes, "
            f"exceeds max {args.release_size_max}"
        )

    if not args.allow_profile_build_mismatch and ap_build not in profile:
        errors.append(
            f"firmware AP build {ap_build} does not match profile {profile}; "
            "use an exact profile for this firmware instead of replacing another build"
        )

    target_text = target_h.read_text(encoding="utf-8", errors="replace") if target_h.exists() else ""
    for macro in required_target_macros:
        if not re.search(rf"^\s*#define\s+{re.escape(macro)}\b", target_text, re.MULTILINE):
            errors.append(f"target.h missing required macro {macro}")
    for label, macros in required_macro_groups:
        if not any(re.search(rf"^\s*#define\s+{re.escape(macro)}\b", target_text, re.MULTILINE) for macro in macros):
            errors.append(f"target.h missing required macro group {label}: one of {', '.join(macros)}")

    # BUILD_FINGERPRINT is provenance metadata; the exploit never reads it at
    # runtime, so a missing/wrong fingerprint is a loud warning, not a hard gate.
    fingerprint_match = re.search(r'#define\s+BUILD_FINGERPRINT\s+[\s\\]*"([^"]+)"', target_text)
    if fingerprint_match:
        fingerprint = fingerprint_match.group(1)
        if ap_build not in fingerprint:
            print(
                f"[WARN] BUILD_FINGERPRINT does not contain AP build {ap_build}: "
                f"{fingerprint}; supply the fingerprint input or a fota.zip build for provenance",
                file=sys.stderr,
            )
    else:
        print(
            f"[WARN] target.h does not define a parseable BUILD_FINGERPRINT; "
            "provenance metadata will be missing from the port",
            file=sys.stderr,
        )

    expected_p0_include = f'targets/{profile}/p0_fingerprint.h'
    if target_text and expected_p0_include not in target_text:
        errors.append(f"target.h does not reference {expected_p0_include}")

    p0_text = p0_h.read_text(encoding="utf-8", errors="replace") if p0_h.exists() else ""
    rows = re.findall(r"\{\s*0x[0-9a-fA-F]{6}ULL,\s*\{", p0_text)
    if p0_text and len(rows) != 32:
        errors.append(f"p0_fingerprint.h should contain 32 slide rows, found {len(rows)}")
    elif p0_text:
        slides = [int(match, 16) for match in re.findall(r"\{\s*0x([0-9a-fA-F]{6})ULL,\s*\{", p0_text)]
        if sorted(slides) != [i * 0x10000 for i in range(32)]:
            errors.append("p0_fingerprint.h must contain every slide 0x000000..0x1f0000 exactly once")
        row_blocks = re.findall(
            r"\{\s*0x[0-9a-fA-F]{6}ULL,\s*\{(?P<words>.*?)\}\s*\}",
            p0_text,
            re.DOTALL,
        )
        for index, block in enumerate(row_blocks, 1):
            words = re.findall(r"0x[0-9a-fA-F]{16}ULL", block)
            if len(words) != 8:
                errors.append(f"p0_fingerprint row {index} has {len(words)} words, expected 8")

    if args.kernel:
        if not args.kernel.exists():
            errors.append(f"kernel file not found: {args.kernel}")
        else:
            size = args.kernel.stat().st_size
            if size < 16 * 1024 * 1024:
                errors.append(f"raw kernel unexpectedly small: {size} bytes")

    if args.btf:
        if not args.btf.exists():
            errors.append(f"BTF file not found: {args.btf}")
        else:
            btf = args.btf.read_bytes()
            if len(btf) < 24 or btf[:4] != b"\x9f\xeb\x01\x00":
                errors.append(f"BTF file does not start with validated little-endian raw BTF header: {args.btf}")

    if args.kernelsu_path and not args.kernelsu_path.exists():
        errors.append(f"KernelSU late-load artifact not found: {args.kernelsu_path}")
    if args.kernelsu_ko_path and not args.kernelsu_ko_path.exists():
        errors.append(f"KernelSU KO artifact not found: {args.kernelsu_ko_path}")

    if args.kernel_release:
        match = re.match(r"\d+\.\d+\.\d+", args.kernel_release)
        release_leading = match.group(0) if match else args.kernel_release
        if args.kernel_version != release_leading:
            errors.append(
                f"kernel version {args.kernel_version} does not match the leading "
                f"three parts of the detected kernel release {args.kernel_release} "
                f"({release_leading}); feed kernelVersions must equal uname -r's leading 3 parts"
            )

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


def cmd_validate_analysis(args: argparse.Namespace) -> int:
    target_h = args.payloads_repo / "src" / "targets" / args.profile / "target.h"
    errors: list[str] = []
    if not target_h.exists():
        errors.append(f"missing target header: {target_h}")
        target_text = ""
    else:
        target_text = target_h.read_text(encoding="utf-8", errors="replace")

    if not args.vmlinux_nm.exists():
        errors.append(f"missing vmlinux nm dump: {args.vmlinux_nm}")
        nm = {}
    else:
        nm = parse_nm(args.vmlinux_nm)
        if len(nm) < 1000:
            errors.append(f"vmlinux nm dump has too few symbols: {len(nm)}")

    base = parse_macro_int(target_text, "KIMAGE_TEXT_BASE")
    if base is None:
        errors.append("target.h missing numeric KIMAGE_TEXT_BASE")

    symbol_checks = {
        "CALL_USERMODEHELPER_EXEC_WORK_OFF": "call_usermodehelper_exec_work",
        "NOOP_LLSEEK_OFF": "noop_llseek",
        "COPY_SPLICE_READ_OFF": "generic_file_splice_read",
        "CONFIGFS_READ_ITER_OFF": "configfs_read_iter",
        "CONFIGFS_BIN_WRITE_ITER_OFF": "configfs_bin_write_iter",
        "ASHMEM_IOCTL_OFF": "ashmem_ioctl",
        "ASHMEM_COMPAT_IOCTL_OFF": "compat_ashmem_ioctl",
        "ASHMEM_MMAP_OFF": "ashmem_mmap",
        "ASHMEM_OPEN_OFF": "ashmem_open",
        "ASHMEM_RELEASE_OFF": "ashmem_release",
        "ASHMEM_SHOW_FDINFO_OFF": "ashmem_show_fdinfo",
        "ANON_PIPE_BUF_OPS_OFF": "anon_pipe_buf_ops",
        "ASHMEM_FOPS_OFF": "ashmem_fops",
        "KMALLOC_CACHES_OFF": "kmalloc_caches",
        "SYSTEM_UNBOUND_WQ_OFF": "system_unbound_wq",
        "INIT_TASK_OFF": "init_task",
        "ROOT_TASK_GROUP_OFF": "root_task_group",
    }
    if base is not None and nm:
        for macro, symbol in symbol_checks.items():
            expected = parse_macro_value(target_text, macro)
            resolved = resolve_symbol(nm, macro, symbol)
            if expected is None:
                errors.append(f"target.h missing numeric {macro}")
            elif resolved is None:
                errors.append(f"vmlinux nm missing symbol {symbol} for {macro}")
            else:
                found_symbol, actual_addr = resolved
                if actual_addr - base != expected:
                    errors.append(
                        f"{macro} mismatch: target.h=0x{expected:x} "
                        f"nm({found_symbol})-base=0x{actual_addr - base:x}"
                    )

    if args.btf_raw:
        if not args.btf_raw.exists():
            errors.append(f"missing BTF raw dump: {args.btf_raw}")
        else:
            btf_text = args.btf_raw.read_text(encoding="utf-8", errors="replace")
            for needle in ("STRUCT 'file_operations'", "STRUCT 'task_struct'", "STRUCT 'page'"):
                if needle not in btf_text:
                    errors.append(f"BTF raw dump missing {needle}")

    if args.worker_objdump:
        if not args.worker_objdump.exists():
            errors.append(f"missing worker_thread objdump: {args.worker_objdump}")
        else:
            worker_text = args.worker_objdump.read_text(encoding="utf-8", errors="replace")
            if "worker_thread" not in worker_text or "schedule" not in worker_text:
                errors.append("worker_thread objdump must include worker_thread and schedule call evidence")

    if args.modinfo:
        if not args.modinfo.exists():
            errors.append(f"missing modinfo output: {args.modinfo}")
        else:
            modinfo_text = args.modinfo.read_text(encoding="utf-8", errors="replace")
            if "vermagic:" not in modinfo_text:
                errors.append("modinfo output missing vermagic")
            if args.kernel_release and args.kernel_release not in modinfo_text:
                errors.append(f"modinfo vermagic does not contain kernel release {args.kernel_release}")

    if args.struct_offsets:
        if not args.struct_offsets.exists():
            errors.append(f"missing struct offsets JSON: {args.struct_offsets}")
        else:
            try:
                btf = json.loads(args.struct_offsets.read_text(encoding="utf-8"))
                structs = btf.get("structs", {})
            except (json.JSONDecodeError, OSError) as exc:
                errors.append(f"struct offsets JSON unreadable: {exc}")
                structs = {}
            if structs:
                task_members = structs.get("task_struct", {}).get("members", {})
                for member, macro in (
                    ("usage", "FAKE_TASK_USAGE_OFF"),
                    ("prio", "FAKE_TASK_PRIO_OFF"),
                    ("normal_prio", "FAKE_TASK_NORMAL_PRIO_OFF"),
                    ("sched_task_group", "FAKE_TASK_TASK_GROUP_OFF"),
                    ("pi_lock", "FAKE_TASK_PI_LOCK_OFF"),
                    ("pi_waiters", "FAKE_TASK_PI_WAITERS_OFF"),
                    ("pi_top_task", "FAKE_TASK_PI_TOP_TASK_OFF"),
                    ("pi_blocked_on", "FAKE_TASK_PI_BLOCKED_ON_OFF"),
                ):
                    if member in task_members:
                        expected = parse_macro_value(target_text, macro)
                        if expected is None:
                            errors.append(f"target.h missing numeric {macro}")
                        elif expected != task_members[member]:
                            errors.append(
                                f"{macro} mismatch: target.h=0x{expected:x} BTF task_struct.{member}=0x{task_members[member]:x}"
                            )
                for member, macro in (
                    ("unlocked_ioctl", "FOPS_IOCTL_OFF"),
                    ("compat_ioctl", "FOPS_COMPAT_IOCTL_OFF"),
                    ("show_fdinfo", "FOPS_SHOW_FDINFO_OFF"),
                    ("splice_read", "FOPS_SPLICE_READ_OFF"),
                ):
                    fops_members = structs.get("file_operations", {}).get("members", {})
                    if member in fops_members:
                        expected = parse_macro_value(target_text, macro)
                        if expected is not None and expected != fops_members[member]:
                            errors.append(
                                f"{macro} mismatch: target.h=0x{expected:x} BTF file_operations.{member}=0x{fops_members[member]:x}"
                            )
                page_members = structs.get("page", {}).get("members", {})
                if "compound_head" in page_members:
                    expected = parse_macro_value(target_text, "STRUCT_PAGE_COMPOUND_HEAD_OFF")
                    if expected is not None and expected != page_members["compound_head"]:
                        errors.append(
                            f"STRUCT_PAGE_COMPOUND_HEAD_OFF mismatch: target.h=0x{expected:x} "
                            f"BTF page.compound_head=0x{page_members['compound_head']:x}"
                        )

    for label, path in (
        ("check_symbol", args.check_symbol_log),
        ("module audit", args.module_audit_log),
    ):
        if path:
            if not path.exists():
                errors.append(f"missing {label} log: {path}")
            else:
                text = path.read_text(encoding="utf-8", errors="replace").lower()
                bad_words = ("missing", "mismatch", "error", "failed")
                if any(word in text for word in bad_words) and "zero missing" not in text:
                    errors.append(f"{label} log contains failure words")

    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("analysis gates OK")
    return 0


def parse_nm(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
            name = parts[-1]
            # Samsung mangles kallsyms names with a $<32-hex> hash suffix
            # (e.g. worker_thread$f31e2447a3fdcb60f4b193f95acd647c). .cfi_jt
            # entries are CFI jump-table thunks, not the real functions. The
            # nm dump is address-sorted, so keeping the first occurrence of
            # each de-mangled name yields the real function address.
            if ".cfi_jt" in name:
                continue
            name = re.sub(r"\$[0-9a-f]{32}$", "", name)
            if name not in symbols:
                symbols[name] = int(parts[0], 16)
    return symbols


def parse_macro_int(text: str, macro: str) -> int | None:
    match = re.search(rf"^\s*#define\s+{re.escape(macro)}\s+\(?\s*(0x[0-9a-fA-F]+|\d+)", text, re.MULTILINE)
    if not match:
        return None
    return int(match.group(1), 0)


def parse_macro_value(text: str, macro: str) -> int | None:
    """Numeric value of a macro, resolving alias/expression definitions too
    (a36xq-style headers define FAKE_TASK_* as aliases of TASK_*)."""
    m = re.search(rf"(?m)^\s*#define\s+{re.escape(macro)}\s+([^\n\\]+)", text)
    if not m:
        return None
    return _eval_macro_rhs(text, m.group(1))


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
    report = repo / "src" / "targets" / profile / "port-report.md"
    if report.exists():
        derived = sum(1 for l in report.read_text(encoding="utf-8").splitlines() if l.startswith("- [DERIVED]"))
        scaffolded = sum(1 for l in report.read_text(encoding="utf-8").splitlines() if l.startswith("- [SCAFFOLD]"))
        print(f"[OK] derivation report: {derived} derived, {scaffolded} scaffolded constants")
    else:
        print("[TODO] derivation report (port-report.md) missing")
    print("[TODO] verify scaffolded constants (phys load, tracefs event id, pselect shift, fake-task layout)")
    print("[TODO] build and audit exact KernelSU KO plus ksud late-load artifact (or document reuse)")
    print("[TODO] run hardware validation on an owned or authorized device")
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
