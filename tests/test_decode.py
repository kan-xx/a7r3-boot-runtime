#!/usr/bin/env python3
"""Offline unit test for boot-guard dual-slot 256B journal & observer decoders."""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "boot-guard"))
from journal_decode import (  # noqa: E402
    DB,
    NONCE,
    gx,
    observer,
    restore_intent,
    restore_result,
    summarize,
)


def make_gx(phase: int = 2, seq: int = 2, boot: str = "aaaaaaaa-1111-2222-3333-444444444444", error: int = 0) -> bytes:
    b = bytearray(256)
    b[:8] = b"A7GXST01"
    struct.pack_into("<IIQII", b, 8, 1, 256, seq, phase, 0x3110F20E if phase in (4, 6) else 0)
    b[32:48] = bytes.fromhex(NONCE)
    b[48:84] = boot.encode("ascii")
    b[88:120] = bytes.fromhex(DB)
    struct.pack_into("<I", b, 120, 151)
    if phase in (4, 6):
        struct.pack_into("<Q", b, 124, 106)
    if phase == 6:
        struct.pack_into("<I", b, 132, error)
    b[224:] = hashlib.sha256(b[:224]).digest()
    return bytes(b)


def main() -> None:
    checks = 0

    def ck(v: bool) -> None:
        nonlocal checks
        checks += 1
        assert v

    for phase in range(1, 7):
        r = gx(make_gx(phase, error=39))
        ck(r["valid_content"])
        ck(r["phase"] == phase)
        if phase == 6:
            ck(r["owner_error"] == 39 and r["im_start"] == 106)

    for p in (0, 7):
        ck(not gx(make_gx(p))["valid_content"])
    for n in (0, 16, 255, 257):
        ck(not gx(bytes(n))["valid_content"])
    for off in (0, 8, 16, 32, 48, 88, 224):
        b = bytearray(make_gx())
        b[off] ^= 1
        ck(not gx(bytes(b))["valid_content"])

    a = gx(make_gx(2, 2))
    b_rec = gx(make_gx(1, 1))
    ck(summarize(a, b_rec, a["boot"])["next_source_branch"] == "CONFIRMED_same_boot")
    ck(
        summarize(a, b_rec, "bbbbbbbb-1111-2222-3333-444444444444")["next_source_branch"]
        == "publish_STARTED_then_wait_current_READY"
    )
    ck(summarize(gx(make_gx(1, 3)), a)["reason"] == 2)
    ck(summarize(gx(make_gx(2, 5)), a)["reason"] == 1)
    ck(summarize(gx(bytes(32)), a)["reason"] == 1)
    ck(summarize(None, None)["next_source_branch"] == "publish_STARTED_then_wait_current_READY")

    obs = bytearray(256)
    struct.pack_into("<4I", obs, 0, 0x314F4241, 1, 0x3110E115, 256)
    struct.pack_into("<4Q", obs, 64, 1, 1, 1_000_000_000, 61_000_000_000)
    struct.pack_into("<8I", obs, 96, 36, 151, 1, 0, 128, 2, 5, 0)
    struct.pack_into("<4I", obs, 240, 1, 0, 1, 1)
    robs = observer(bytes(obs))
    ck(robs["elapsed_ms"] == 60000 and robs["restored"] == 1 and robs["guard_reason"] == 5)

    ri = bytearray(248)
    ri[:8] = b"A7RV1401"
    struct.pack_into("<II", ri, 8, 1, 248)
    ri[16:52] = b"cccccccc-1111-2222-3333-444444444444"
    struct.pack_into("<IQQQ", ri, 56, 151, 106, 10, 20)
    ri[216:] = hashlib.sha256(ri[:216]).digest()
    ck(restore_intent(bytes(ri))["digest_valid"] is True)
    ck(restore_result(struct.pack("<10I", 0, 1, 1, 1, 1, 1, 1, 1, 1, 0))["readonly"] == 1)

    print(json.dumps({"passed": True, "test": "journal_decode", "checks": checks}))


if __name__ == "__main__":
    main()
