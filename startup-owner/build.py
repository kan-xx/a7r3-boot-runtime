#!/usr/bin/env python3
"""Build liba7r_startup_full_v14.so and libproBF.so against extracted FW 3.10 ABI."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "imdb-registry"))
from build_imdb import DT_RELCOUNT, Elf32View, PT_LOAD  # noqa: E402

PT_GNU_STACK = 0x6474E551
PF_X = 0x1
PF_W = 0x2


def patch_dt_relcount_zero(elf_path: Path) -> bytes:
    b = bytearray(elf_path.read_bytes())
    view = Elf32View(b)
    dyn_sec = view.section_by_name(".dynamic")
    dyn_off = int(dyn_sec["sh_offset"])
    for idx, d_tag, _ in view.dynamic_tags():
        if d_tag == DT_RELCOUNT:
            struct.pack_into("<I", b, dyn_off + 8 * idx + 4, 0)
    # Audit segments: zero RWX PT_LOAD and non-executable PT_GNU_STACK
    checked = Elf32View(b)
    for ph in checked.phdrs:
        if ph["p_type"] == PT_LOAD and (ph["p_flags"] & (PF_W | PF_X)) == (PF_W | PF_X):
            raise AssertionError("Forbidden RWX PT_LOAD segment")
        if ph["p_type"] == PT_GNU_STACK and (ph["p_flags"] & PF_X):
            raise AssertionError("Executable PT_GNU_STACK is forbidden")
    out = bytes(b)
    elf_path.write_bytes(out)
    return out


def build_startup_owner(fw_root: Path, out_dir: Path, zig: str | None = None) -> dict:
    zig_bin = zig or os.environ.get("ZIG") or shutil.which("zig")
    if not shutil.which(zig_bin) and not Path(zig_bin).is_file():
        raise FileNotFoundError("zig compiler not found; set ZIG=/path/to/zig or pass --zig")

    root_lib = fw_root / "nflasha7/export/lib"
    usr_lib = fw_root / "nflasha15/export/lib"
    out_dir.mkdir(parents=True, exist_ok=True)

    owner_sources = [
        HERE / "core/native.c",
        HERE / "core/sem_port.c",
        HERE / "core/ready_record.c",
        HERE / "core/registration.c",
        HERE / "platform/platform.c",
        HERE / "platform/maps.c",
        HERE / "bootstrap/bootstrap_gate.c",
        HERE / "bootstrap/ingress.c",
        HERE / "bundle/bundle.c",
        HERE / "bundle/ui_candidate.c",
        HERE / "bundle/barrier_adapter.c",
        HERE / "barrier/ports.c",
        HERE / "barrier/barrier.c",
        HERE / "barrier/warmup.c",
        HERE / "barrier/policy.c",
        HERE / "lifecycle/owner.c",
        HERE / "lifecycle/completion.c",
        REPO / "exit-bridge/loader.c",
        HERE / "core/owner_report_cache.c",
        HERE / "autoload/touch_owner_gate.c",
        HERE / "autoload/optional_loader.c",
        HERE / "autoload/native_loader.c",
        HERE / "autoload/boot_manifest.c",
        HERE / "autoload/verify_file_hash.c",
    ]

    owner_out = out_dir / "liba7r_startup_full_v14.so"
    common_flags = [
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
    ]
    cmd = [
        *common_flags,
        "-DFB_PROTECTED_BOOT_TRIAL",
        "-I" + str(HERE / "barrier"),
        "-I" + str(HERE / "core"),
        "-Wl,-soname,liba7r_startup_full_v14.so",
        "-Wl,--version-script=" + str(HERE / "core/exports.map"),
        *map(str, owner_sources),
        str(root_lib / "libpthread-2.11.2.so"),
        str(root_lib / "libdl-2.11.2.so"),
        str(root_lib / "libc-2.11.2.so"),
        "-Wl,--no-as-needed",
        str(usr_lib / "libosal_uipc.so"),
        "-o",
        str(owner_out),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"startup-owner build failed:\n{res.stderr}")
    owner_raw = patch_dt_relcount_zero(owner_out)

    bf_out = out_dir / "libproBF.so"
    bf_cmd = [
        *common_flags,
        "-Wl,-soname,libproBF.so",
        str(HERE / "core/query.c"),
        str(root_lib / "libdl-2.11.2.so"),
        str(root_lib / "libc-2.11.2.so"),
        "-o",
        str(bf_out),
    ]
    res_bf = subprocess.run(bf_cmd, capture_output=True, text=True)
    if res_bf.returncode != 0:
        raise RuntimeError(f"libproBF.so build failed:\n{res_bf.stderr}")
    bf_raw = patch_dt_relcount_zero(bf_out)

    return {
        "owner": {
            "name": owner_out.name,
            "bytes": len(owner_raw),
            "sha256": hashlib.sha256(owner_raw).hexdigest(),
        },
        "query_plugin": {
            "name": bf_out.name,
            "bytes": len(bf_raw),
            "sha256": hashlib.sha256(bf_raw).hexdigest(),
        },
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fw-root", type=Path, default=os.environ.get("A7R3_FW_ROOT"))
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--zig", help="Path to zig binary")
    args = p.parse_args()
    if not args.fw_root:
        p.error("Provide --fw-root or set A7R3_FW_ROOT")
    print(json.dumps(build_startup_owner(Path(args.fw_root), args.out_dir, args.zig), indent=2))


if __name__ == "__main__":
    main()
