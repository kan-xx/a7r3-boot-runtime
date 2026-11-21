#!/usr/bin/env python3
"""Build static ARMv7 boot-guard daemon (a7r-boot-guard-v21.elf)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


def find_zig(explicit: str | None) -> str:
    cand = explicit or os.environ.get("ZIG") or shutil.which("zig")
    if not shutil.which(cand) and not Path(cand).is_file():
        raise FileNotFoundError("zig compiler not found; set ZIG=/path/to/zig or pass --zig")
    return cand


def build_guard(output: Path, zig: str | None = None) -> dict:
    zig_bin = find_zig(zig)
    sources = [HERE / "boot_guard.c", HERE / "transaction.c", HERE / "monitor.c"]
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
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
        "-I" + str(HERE),
        *map(str, sources),
        "-o",
        str(output),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"boot-guard build failed:\n{res.stderr}")
    raw = output.read_bytes()
    return {
        "target": output.name,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True, help="Output ELF path")
    p.add_argument("--zig", help="Path to zig binary")
    args = p.parse_args()
    print(json.dumps(build_guard(args.output, args.zig), indent=2))


if __name__ == "__main__":
    main()
