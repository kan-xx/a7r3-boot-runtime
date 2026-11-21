#!/usr/bin/env python3
"""Build constructor-free libsencore ProductInfo dlopen canary (libproFA.so)."""
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


def build_canary(output: Path, zig: str | None = None) -> dict:
    zig_bin = zig or os.environ.get("ZIG") or shutil.which("zig")
    if not shutil.which(zig_bin) and not Path(zig_bin).is_file():
        raise FileNotFoundError("zig compiler not found; set ZIG=/path/to/zig or pass --zig")
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
        "-Wl,-z,noexecstack",
        "-Wl,-soname,libproFA.so",
        str(HERE / "canary.c"),
        "-o",
        str(output),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"loader-canary build failed:\n{res.stderr}")
    raw = patch_dt_relcount_zero(output)
    return {
        "name": output.name,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--zig", help="Path to zig binary")
    args = p.parse_args()
    print(json.dumps(build_canary(args.output, args.zig), indent=2))


if __name__ == "__main__":
    main()
