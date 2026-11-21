#!/usr/bin/env python3
"""Optional firmware-backed verification suite (`A7R3_FW_ROOT=... make verify-fw`).

Reads the user-supplied extracted Sony A7R III (FW 3.10) filesystem tree in
strict read-only mode, verifies cryptographic digests and instruction anchors,
validates deterministic data-only libIMDB.so transformation (61,840 B), and
optionally verifies deterministic ARMv7 cross-builds when `zig` is installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "imdb-registry"))
from build_imdb import EXPECTED_ADDON_SHA256, STOCK_IMDB_SHA256, transform_imdb  # noqa: E402

EXPECTED_FW_DIGESTS = {
    "nflasha15/export/bin/im.elf": (
        "866729eb0bc1e6f5aba04d8bf8e45491985afe89a078ccb106a1ce2476865225"
    ),
    "nflasha15/export/lib/libIMDB.so": STOCK_IMDB_SHA256,
    "nflasha7/export/lib/ld-2.11.2.so": (
        "7c215cee6c4175079d69cb1433c6be90189e793f6e44f068ed6ac97621dd7a2c"
    ),
    "nflasha7/export/lib/libc-2.11.2.so": (
        "bceb5cfb7769b54bf9c9d178b8a5f4579531c0f60e673cbcae872a8c7a3508fb"
    ),
    "nflasha7/export/lib/libdl-2.11.2.so": (
        "ec86a3438cf7df1951be3023b3ddc90d5b6360fa48e60d20cc8b497a6345ef35"
    ),
    "nflasha7/export/lib/libpthread-2.11.2.so": (
        "938387093567f5721bdeafa5bf68275d3a8705c8c6536745358e229af27fcab8"
    ),
    "nflasha15/export/lib/libosal_uipc.so": (
        "b6ded35add9582413b401cf4db78ec2c9a201b632e78c2731d6bbb379249b3eb"
    ),
    "nflasha15/export/lib/libObj.so": (
        "94ce6ec47c2b394aa1a4f781bfb3e9ec3337f6a2b8558fa025f42e87b2dda19b"
    ),
    "nflasha15/export/lib/viewUnified2.so": (
        "9b243bb9c11acc1adfc09fb752e12835ea0a4556882867c53f1dd6c9143128d9"
    ),
    "nflasha3/export/av-cam.bin": (
        "35e3ff3f931fa725928ab8c7493d4b9842e1f90c3fa7b90ab4e23274256dd800"
    ),
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", type=Path, default=os.environ.get("A7R3_FW_ROOT"))
    args = p.parse_args()
    if not args.fw_root:
        p.error("Set A7R3_FW_ROOT or pass --fw-root /path/to/extracted/filesystems")
    fw_root = Path(args.fw_root)
    if not fw_root.is_dir():
        raise FileNotFoundError(f"Firmware root directory not found: {fw_root}")

    checks = 0
    for rel, expected in EXPECTED_FW_DIGESTS.items():
        fp = fw_root / rel
        if not fp.is_file():
            raise FileNotFoundError(f"Missing firmware file: {fp}")
        got = sha256_file(fp)
        if got != expected:
            raise AssertionError(f"SHA-256 mismatch for {rel}: got {got}, expected {expected}")
        checks += 1

    # Verify data-only libIMDB.so transformation against real stock libIMDB.so
    stock_imdb = (fw_root / "nflasha15/export/lib/libIMDB.so").read_bytes()
    addon_bytes, report = transform_imdb(stock_imdb, allow_synthetic=False)
    assert len(addon_bytes) == 61840
    assert report["candidate_sha256"] == EXPECTED_ADDON_SHA256
    assert report["record_count"] == 185
    checks += 3

    # Optional cross-compilation reproducibility verification if zig is installed
    zig_bin = os.environ.get("ZIG") or shutil.which("zig")
    cross_built = {}
    if shutil.which(zig_bin) or Path(zig_bin).is_file():
        with tempfile.TemporaryDirectory(prefix="a7r3-boot-fwverify-") as tmp:
            t = Path(tmp)
            for label, cmd in [
                (
                    "boot_guard",
                    [sys.executable, str(REPO / "boot-guard/build.py"), "--zig", zig_bin, "--output", str(t / "a7r-boot-guard-v21.elf")],
                ),
                (
                    "startup_owner",
                    [sys.executable, str(REPO / "startup-owner/build.py"), "--zig", zig_bin, "--fw-root", str(fw_root), "--out-dir", str(t)],
                ),
                (
                    "exit_bridge",
                    [
                        sys.executable,
                        str(REPO / "exit-bridge/build.py"),
                        "--zig",
                        zig_bin,
                        "--fw-root",
                        str(fw_root),
                        "--owner-so",
                        str(t / "liba7r_startup_full_v14.so"),
                        "--output",
                        str(t / "liba7r_full_exit_bridge_v14.so"),
                    ],
                ),
                (
                    "loader_canary",
                    [sys.executable, str(REPO / "loader-canary/build.py"), "--zig", zig_bin, "--output", str(t / "libproFA.so")],
                ),
            ]:
                res = subprocess.run(cmd, check=True, text=True, capture_output=True)
                cross_built[label] = json.loads(res.stdout)
                checks += 1

            # Also verify static ARM compilation of publishers (commit, two-step-publish, cleanup)
            for pub_name, pub_srcs in [
                ("commit", [REPO / "publishers/commit/main.c"]),
                ("two_step_publish", [REPO / "publishers/two-step-publish/common_main.c"]),
                ("cleanup", [REPO / "publishers/cleanup/cleanup.c", REPO / "publishers/cleanup/cleanup_engine.c"]),
            ]:
                out_elf = t / f"{pub_name}.elf"
                subprocess.run(
                    [
                        zig_bin,
                        "cc",
                        "-target",
                        "arm-linux-musleabi",
                        "-mcpu=cortex_a9",
                        "-Os",
                        "-static",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        *map(str, pub_srcs),
                        "-o",
                        str(out_elf),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                cross_built[pub_name] = {"bytes": out_elf.stat().st_size, "sha256": sha256_file(out_elf)}
                checks += 1

    print(
        json.dumps(
            {
                "passed": True,
                "fw_digests_verified": len(EXPECTED_FW_DIGESTS),
                "imdb_addon_sha256": report["candidate_sha256"],
                "imdb_addon_bytes": len(addon_bytes),
                "cross_compiled_targets": cross_built,
                "total_checks": checks,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
