#!/usr/bin/env python3
"""Build DT_FINI teardown ordering bridge (liba7r_full_exit_bridge_v14.so)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "startup-owner"))
from build import patch_dt_relcount_zero  # noqa: E402


def build_exit_bridge(fw_root: Path, owner_so: Path, output: Path, zig: str | None = None) -> dict:
    zig_bin = zig or os.environ.get("ZIG") or shutil.which("zig")
    if not shutil.which(zig_bin) and not Path(zig_bin).is_file():
        raise FileNotFoundError("zig compiler not found; set ZIG=/path/to/zig or pass --zig")

    root_lib = fw_root / "nflasha7/export/lib"
    usr_lib = fw_root / "nflasha15/export/lib"
    output.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        zig_bin,
        "cc",
        "-target",
        "arm-linux-gnueabi",
        "-mcpu=cortex_a9",
        "-marm",
        "-mfloat-abi=soft",
        "-Os",
        "-fno-builtin",
        "-fno-stack-protector",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-nostdlib",
        "-shared",
        "-fPIC",
        "-fvisibility=hidden",
        "-Wl,--hash-style=sysv",
        "-Wl,-z,now",
        "-Wl,-z,defs",
        "-Wl,-z,noexecstack",
        "-Wl,-soname,liba7r_full_exit_bridge_v14.so",
        "-Wl,--version-script=" + str(HERE / "exports.map"),
        str(HERE / "bridge.c"),
        "-Wl,--no-as-needed",
        str(owner_so),
        str(usr_lib / "CautionConfig.so"),
        str(usr_lib / "viewUnified2.so"),
        str(usr_lib / "libObj.so"),
        str(usr_lib / "dataflowInfraFramework.so"),
        str(usr_lib / "libosal_uipc.so"),
        str(root_lib / "libc-2.11.2.so"),
        "-o",
        str(output),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"exit-bridge build failed:\n{res.stderr}")
    raw = patch_dt_relcount_zero(output)
    return {
        "name": output.name,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", type=Path, default=os.environ.get("A7R3_FW_ROOT"))
    p.add_argument("--owner-so", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--zig", help="Path to zig binary")
    args = p.parse_args()
    if not args.fw_root:
        p.error("Provide --fw-root or set A7R3_FW_ROOT")
    print(json.dumps(build_exit_bridge(Path(args.fw_root), args.owner_so, args.output, args.zig), indent=2))


if __name__ == "__main__":
    main()
