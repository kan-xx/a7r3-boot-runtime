#!/usr/bin/env python3
"""Generate synchronized deployment identity headers from user-compiled artifacts.

Eliminates manual byte-size and SHA-256 editing across `boot-guard/configuration.h`,
`startup-owner/core/identity.h`, and `publishers/two-step-publish/publication_identity.h`
when users build their own release binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
STOCK_IMDB_SHA256 = "0f4d6355c0f8903714f8af506da7c4d357c9d66ed725fbc9f344fe82c928a321"
STOCK_IMDB_BYTES = 31468

REF_ANCHOR_C = (
    "{45,233,240,65,0,175,136,70,255,247,244,254,5,70,216,177,198,104,52,70,"
    "9,224,163,104,152,69,5,209,99,104,0,32,1,51,99,96,189,232,240,129,36,104,"
    "0,44,243,209,12,32,253,247,126,233,96,177,192,248,8,128,1,35,6,96,67,96,"
    "232,96,32,70,189,232,240,129,111,240,3,0,189,232,240,129,111,240,2,0,189,232}"
)


def _c_byte_array(raw: bytes) -> str:
    return "{" + ",".join(str(b) for b in raw) + "}"


def _file_info(path: Path) -> tuple[int, str, bytes]:
    data = path.read_bytes()
    digest = hashlib.sha256(data).digest()
    return len(data), digest.hex(), digest


def generate_headers(
    artifacts_dir: Path,
    *,
    nonce_hex: str | None = None,
    out_root: Path | None = None,
    stock_imdb_sha_hex: str = STOCK_IMDB_SHA256,
    stock_imdb_bytes: int = STOCK_IMDB_BYTES,
) -> dict[str, object]:
    if not nonce_hex:
        raw_nonce = os.urandom(16)
        if not any(raw_nonce):
            raw_nonce = b"\x01" + bytes(15)
        nonce_hex = raw_nonce.hex()
    nonce_bytes = bytes.fromhex(nonce_hex)
    if len(nonce_bytes) != 16 or not any(nonce_bytes):
        raise ValueError("--nonce must be 32 hex chars representing 16 non-zero bytes")

    imdb_path = artifacts_dir / "libIMDB.candidate.so"
    if not imdb_path.is_file():
        imdb_path = artifacts_dir / "libIMDB.so"
    if not imdb_path.is_file():
        raise FileNotFoundError(f"Expected libIMDB.candidate.so or libIMDB.so in {artifacts_dir}")

    owner_path = artifacts_dir / "liba7r_startup_full_v14.so"
    if not owner_path.is_file():
        raise FileNotFoundError(f"Expected liba7r_startup_full_v14.so in {artifacts_dir}")

    imdb_bytes, imdb_sha_hex, imdb_sha_raw = _file_info(imdb_path)
    owner_bytes, owner_sha_hex, _ = _file_info(owner_path)
    stock_sha_raw = bytes.fromhex(stock_imdb_sha_hex)

    target_root = out_root or REPO
    cfg_h = target_root / "boot-guard/configuration.h"
    id_h = target_root / "startup-owner/core/identity.h"
    pub_h = target_root / "publishers/two-step-publish/publication_identity.h"
    for p in (cfg_h, id_h, pub_h):
        p.parent.mkdir(parents=True, exist_ok=True)

    cfg_h.write_text(
        f'static const struct gx_config configuration={{.target="libIMDB.so",'
        f'.retained="libIMDB.a7r-retired-{nonce_hex}.so",'
        f'.standby="libIMDB.a7r-stock-{nonce_hex}.so",'
        f".original_bytes={stock_imdb_bytes},.candidate_bytes={imdb_bytes},"
        f".mode=0555,.uid=57285,.gid=1000,.ready_build=0x3110f20e,.wait_ms=60000,"
        f".original={_c_byte_array(stock_sha_raw)},"
        f".candidate={_c_byte_array(imdb_sha_raw)}}};\n",
        encoding="utf-8",
    )

    id_h.write_text(
        "#define OWNER_BUILD 0x3110f20eu\n"
        '#define READY_DIR "/tmp/a7r3-startup-full-v14"\n'
        f'#define ENTRY_RECORD "/tmp/a7r-{nonce_hex}-entry.bin"\n'
        f'#define FAILURE_RECORD "/tmp/a7r-{nonce_hex}-failure.bin"\n'
        f"static const unsigned char installation[]={_c_byte_array(nonce_bytes)};\n"
        f"static const unsigned char ref_anchor[]={REF_ANCHOR_C};\n"
        'static const char*const db_strings[]={"/usr/lib/liba7r_startup_full_v14.so",'
        '"A7R_Lifecycle_Init","A7R_Lifecycle_Exit","A7R_Lifecycle_Sus",'
        '"A7R_Lifecycle_Res","A7R_Lifecycle_Inact","A7R_Lifecycle_Act"};\n',
        encoding="utf-8",
    )

    optional_specs = [
        ("a7r-boot-guard-v21.elf", "/usr/bin/a7r-boot-guard-v21.elf", 0, 0, 365),
        ("liba7r_capture_fresh_v12.so", "/usr/lib/liba7r_capture_fresh_v12.so", 0, 0, 365),
        ("liba7r_menu_product_v21.so", "/usr/lib/liba7r_menu_product_v21.so", 0, 0, 365),
        ("liba7r_touch_full_runtime_v7.so", "/usr/lib/liba7r_touch_full_runtime_v7.so", 0, 0, 365),
        ("a7r_touch_boot_v1.bin", "/usr/lib/a7r_touch_boot_v1.bin", 0, 0, 292),
    ]
    dep_lines = [
        f'{{"/usr/lib/libIMDB.so",{imdb_bytes},57285,1000,365,"{imdb_sha_hex}"}},',
    ]
    for fname, cam_path, uid, gid, mode in optional_specs:
        cand = artifacts_dir / fname
        if cand.is_file():
            sz, sha_hex, _ = _file_info(cand)
            dep_lines.append(f'{{"{cam_path}",{sz},{uid},{gid},{mode},"{sha_hex}"}},')

    pub_h.write_text(
        "#ifndef A7R_TOUCH_PUBLICATION_IDENTITY_H\n"
        "#define A7R_TOUCH_PUBLICATION_IDENTITY_H\n"
        f"#define NEW_OWNER_BYTES {owner_bytes}u\n"
        f'#define NEW_OWNER_SHA "{owner_sha_hex}"\n'
        f'#define ACCEPTED_REGISTRY_SHA "{imdb_sha_hex}"\n'
        f"static const unsigned char accepted_installation[16]={_c_byte_array(nonce_bytes)};\n"
        "struct dep {const char*path;unsigned bytes,uid,gid,mode;const char*hash;};\n"
        "static const struct dep immutable_dependencies[]={\n"
        + "\n".join(dep_lines)
        + "\n};\n#endif\n",
        encoding="utf-8",
    )

    return {
        "nonce": nonce_hex,
        "imdb": {"bytes": imdb_bytes, "sha256": imdb_sha_hex},
        "owner": {"bytes": owner_bytes, "sha256": owner_sha_hex},
        "written": [str(cfg_h), str(id_h), str(pub_h)],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", type=Path, required=True, help="Directory with compiled release binaries")
    parser.add_argument("--nonce", help="Optional 32-hex installation nonce (auto-generated if omitted)")
    parser.add_argument("--out-root", type=Path, help="Optional root directory for generated headers (default: repo root)")
    args = parser.parse_args()
    summary = generate_headers(args.artifacts_dir, nonce_hex=args.nonce, out_root=args.out_root)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
