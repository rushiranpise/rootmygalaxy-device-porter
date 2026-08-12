"""Unit tests for the device-info capture helpers (no adb or device required).

Run with:  python tests/verify_device_info.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from rmg_porter.cli import (  # noqa: E402
    build_four_part,
    device_profile,
    kernel_short,
    parse_getprop,
)

SAMPLE_GETPROP = """\
[ro.product.model]: [SM-S156V]
[ro.product.name]: [a15xtfn]
[ro.product.device]: [a15x]
[ro.product.board]: [a15x]
[ro.hardware]: [mt6835]
[ro.board.platform]: [mt6835]
[ro.soc.manufacturer]: [Mediatek]
[ro.soc.model]: [MT6835]
[ro.product.cpu.abi]: [arm64-v8a]
[ro.build.version.release]: [16]
[ro.build.version.sdk]: [36]
[ro.build.version.oneui]: [80000]
[ro.build.version.security_patch]: [2026-04-05]
[ro.build.version.incremental]: [S156VUDSBDZDC]
[ro.bootloader]: [S156VUDSBDZDC]
[ro.build.fingerprint]: [samsung/a15xtfn/a15x:16/BP2A.250605.031.A3/S156VUDSBDZDC:user/release-keys]
[ro.bootimage.build.fingerprint]: [samsung/a15xtfn/a15x:13/TP1A.220624.014/S156VUDSBDZDC:user/release-keys]
[ro.csc.sales_code]: [TFV]
[ro.omc.multi_csc]: [TFN]
[ro.csc.country_code]: [USA]
[ro.omc.build.version]: [S156VTFNBDZDC]
"""


def test_parse_getprop():
    props = parse_getprop(SAMPLE_GETPROP)
    assert props["ro.product.model"] == "SM-S156V"
    assert props["ro.product.device"] == "a15x"
    assert props["ro.csc.sales_code"] == "TFV"
    assert props["ro.omc.multi_csc"] == "TFN"
    assert props["ro.omc.build.version"] == "S156VTFNBDZDC"
    assert props["ro.build.version.sdk"] == "36"


def test_parse_getprop_empty_and_garbage_lines():
    props = parse_getprop("\r\n[ro.foo]: [bar]\r\nnot a prop line\r\n[ro.baz]: []\r\n")
    assert props["ro.foo"] == "bar"
    assert props["ro.baz"] == ""
    assert "not a prop line" not in props


def test_build_four_part():
    assert (
        build_four_part("S156VUDSBDZDC", "S156VTFNBDZDC")
        == "S156VUDSBDZDC/S156VTFNBDZDC/S156VUDSBDZDC/S156VUDSBDZDC"
    )
    assert build_four_part("A", "B", cp="C") == "A/B/C/A"
    assert build_four_part("", "B") is None
    assert build_four_part("A", "") is None


def test_device_profile():
    assert device_profile("a15x", "S156VUDSBDZDC") == "a15x-S156VUDSBDZDC"
    assert device_profile("a15x", "") is None


def test_kernel_short():
    assert kernel_short("5.15.180-android13-8-32143072") == "5.15.180"
    assert kernel_short("6.6.98") == "6.6.98"
    assert kernel_short("") is None


def _run_all():
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    if failures:
        raise SystemExit(f"{failures} device-info helper test(s) failed")
    print("all device-info helper tests passed")


if __name__ == "__main__":
    _run_all()
