#!/usr/bin/env python3
"""Offline synthetic ELF32 unit test for imdb-registry/build_imdb.py (zero Sony blobs)."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "imdb-registry"))
from build_imdb import (  # noqa: E402
    DEFAULT_STRINGS,
    DT_JMPREL,
    DT_PLTRELSZ,
    DT_REL,
    DT_RELCOUNT,
    DT_RELSZ,
    Elf32View,
    PT_LOAD,
    R_ARM_RELATIVE,
    SHF_ALLOC,
    SHF_EXECINSTR,
    transform_imdb,
)


def make_synthetic_imdb_elf(count: int = 184, insert_idx: int = 112) -> bytes:
    """Construct a valid minimal 32-bit ARM ET_DYN ELF matching libIMDB.so structure."""
    # Layout:
    #   0x0000..0x0034: ELF header (52 B)
    #   0x0034..0x0074: 2 x PT_LOAD program headers (64 B)
    #   0x0100..0x0140: .text (synthetic ARM instructions, RX)
    #   0x0140..0x0170: .dynsym (3 symbols: NULL, imdb_raw, ext_fn)
    #   0x0170..0x0190: .dynstr
    #   0x0190..0x0198: .rel.plt (1 jump slot relocation)
    #   0x1000..      : RW PT_LOAD (vaddr = offset + 0x8000 = 0x9000, delta = 32768)
    #     0x1000 (va 0x9000): .dynamic (7 tags * 8 = 56 B)
    #     0x1040 (va 0x9040): imdb_raw (132 B header + 184 * 44 B descriptors + strings)
    #     after imdb_raw    : .rel.dyn
    #   non-alloc tail: .ARM.attributes, .shstrtab, section headers
    delta = 32768
    b = bytearray(0x1040)

    # .text synthetic machine code bytes (must remain 100% untouched)
    text_off = 0x100
    text_bytes = bytes((0x00, 0x48, 0x2D, 0xE9, 0x1E, 0xFF, 0x2F, 0xE1)) * 8
    b[text_off : text_off + len(text_bytes)] = text_bytes

    dynstr = b"\x00imdb_raw\x00ext_fn\x00"
    dynstr_off = 0x170
    b[dynstr_off : dynstr_off + len(dynstr)] = dynstr

    imdb_off = 0x1040
    imdb_va = imdb_off + delta

    dynsym_off = 0x140
    # sym 0: null; sym 1: imdb_raw; sym 2: ext_fn
    struct.pack_into("<IIIBBH", b, dynsym_off + 16, 1, imdb_va, 132 + count * 44, 0x11, 0, 6)
    struct.pack_into("<IIIBBH", b, dynsym_off + 32, 10, 0, 0, 0x12, 0, 0)

    rel_plt_off = 0x190
    rel_plt_bytes = struct.pack("<II", imdb_va - 8, (2 << 8) | 22)  # R_ARM_JUMP_SLOT
    b[rel_plt_off : rel_plt_off + 8] = rel_plt_bytes

    # Build synthetic imdb_raw payload (132-byte header + 184 * 44-byte table + strings)
    raw_table = bytearray(132 + count * 44)
    struct.pack_into("<I", raw_table, 0, count)
    rel_dyn_entries: list[tuple[int, int]] = []
    str_pool = bytearray()
    str_base_va = imdb_va + len(raw_table)

    for i in range(count):
        if i < insert_idx:
            grp = 1 + (i * 5) // insert_idx  # groups 1..6 before index 112
        elif i == count - 1:
            grp = 40
        else:
            grp = 7 + ((i - insert_idx) * 10) // max(1, count - insert_idx)
        mid = 0x0100 + i
        s_va = str_base_va + len(str_pool)
        str_pool += f"/usr/lib/libmod_{i:03d}.so\x00".encode("ascii")
        desc_off = 132 + i * 44
        struct.pack_into("<11I", raw_table, desc_off, grp, 1, 1, mid, s_va, 0, 0, 0, 0, 0, 0)
        rel_dyn_entries.append((imdb_va + desc_off + 16, R_ARM_RELATIVE))

    while len(str_pool) % 4:
        str_pool.append(0)
    b += raw_table + str_pool

    rel_dyn_off = len(b)
    rel_dyn_va = rel_dyn_off + delta
    # Add one non-relative relocation outside imdb_raw to exercise split ordering
    rel_dyn_entries.append((imdb_va - 4, (2 << 8) | 21))  # R_ARM_GLOB_DAT
    rel_dyn_bytes = b"".join(struct.pack("<II", off, info) for off, info in rel_dyn_entries)
    b += rel_dyn_bytes

    rw_filesz = len(b) - 0x1000
    rw_memsz = rw_filesz + 32  # 32-byte BSS tail to test zero-fill + section relocation

    dyn_off = 0x1000
    dyn_va = dyn_off + delta
    dyn_tags = [
        (DT_REL, rel_dyn_va),
        (DT_RELSZ, len(rel_dyn_bytes)),
        (DT_RELCOUNT, count),
        (DT_JMPREL, rel_plt_off),
        (DT_PLTRELSZ, len(rel_plt_bytes)),
        (0, 0),
    ]
    for idx, (t, v) in enumerate(dyn_tags):
        struct.pack_into("<II", b, dyn_off + idx * 8, t, v)

    # Place non-alloc .ARM.attributes overlapping [zero_start, zero_end) to exercise move logic
    attr_off = len(b)
    attr_bytes = b"A\x0f\x00\x00\x00aeabi\x00\x01\x05\x00\x00\x00\x06\n"
    b += attr_bytes

    shstr = (
        b"\x00.text\x00.dynsym\x00.dynstr\x00.rel.plt\x00.dynamic\x00"
        b".data\x00.rel.dyn\x00.ARM.attributes\x00.shstrtab\x00"
    )
    shstr_off = len(b)
    b += shstr
    b += bytes((-len(b)) % 4)

    def name_off(n: str) -> int:
        return shstr.index(n.encode("ascii") + b"\x00")

    shoff = len(b)
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (name_off(".text"), 1, SHF_ALLOC | SHF_EXECINSTR, text_off, text_off, len(text_bytes), 0, 0, 4, 0),
        (name_off(".dynsym"), 11, SHF_ALLOC, dynsym_off, dynsym_off, 48, 3, 1, 4, 16),
        (name_off(".dynstr"), 3, SHF_ALLOC, dynstr_off, dynstr_off, len(dynstr), 0, 0, 1, 0),
        (name_off(".rel.plt"), 9, SHF_ALLOC, rel_plt_off, rel_plt_off, len(rel_plt_bytes), 2, 1, 4, 8),
        (name_off(".dynamic"), 6, SHF_ALLOC | 1, dyn_va, dyn_off, len(dyn_tags) * 8, 3, 0, 4, 8),
        (name_off(".data"), 1, SHF_ALLOC | 1, imdb_va, imdb_off, len(raw_table) + len(str_pool), 0, 0, 4, 0),
        (name_off(".rel.dyn"), 9, SHF_ALLOC, rel_dyn_va, rel_dyn_off, len(rel_dyn_bytes), 2, 0, 4, 8),
        (name_off(".ARM.attributes"), 0x70000003, 0, 0, attr_off, len(attr_bytes), 0, 0, 1, 0),
        (name_off(".shstrtab"), 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0),
    ]
    for s in sections:
        b += struct.pack("<10I", *s)

    # ELF32 header
    b[0:16] = b"\x7fELF\x01\x01\x01\x00" + bytes(8)
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        b,
        16,
        3,  # ET_DYN
        40,  # EM_ARM
        1,
        text_off,
        52,  # e_phoff
        shoff,
        0x05000000,
        52,
        32,
        2,
        40,
        len(sections),
        len(sections) - 1,
    )
    # Program headers: RX PT_LOAD + RW PT_LOAD
    struct.pack_into("<8I", b, 52, PT_LOAD, 0, 0, 0, 0x200, 0x200, 5, 0x8000)
    struct.pack_into("<8I", b, 84, PT_LOAD, 0x1000, 0x1000 + delta, 0x1000 + delta, rw_filesz, rw_memsz, 6, 0x8000)
    return bytes(b)


def main() -> None:
    checks = 0

    def ck(cond: bool, msg: str = "") -> None:
        nonlocal checks
        if not cond:
            raise AssertionError(msg or "check failed")
        checks += 1

    stock = make_synthetic_imdb_elf()

    # 1. Without allow_synthetic, non-Sony SHA-256 must fail closed.
    try:
        transform_imdb(stock, allow_synthetic=False)
        raise AssertionError("Expected SHA-256 gate rejection")
    except ValueError:
        checks += 1

    # 2. Transform synthetic 184-entry ELF -> 185-entry ELF.
    out, report = transform_imdb(stock, allow_synthetic=True)
    ck(report["record_count"] == 185, "record_count == 185")
    ck(report["module_id"] == 0xFFFE, "module_id == 0xfffe")
    ck(report["insert_index"] == 112, "insert_index == 112")
    ck(report["original_code_unchanged"] is True)

    orig_view = Elf32View(stock)
    new_view = Elf32View(out)

    # 3. Verify 100% of executable bytes match bit-for-bit.
    orig_text = orig_view.section_bytes(int(orig_view.section_by_name(".text")["index"]))
    new_text = new_view.section_bytes(int(new_view.section_by_name(".text")["index"]))
    ck(orig_text == new_text and len(orig_text) == 64, ".text bytes unchanged")

    # 4. Verify contiguous DT_REL + DT_RELSZ == DT_JMPREL (ld-2.11.2.so safety invariant).
    tags = {t: v for _, t, v in new_view.dynamic_tags()}
    ck(tags[DT_REL] + tags[DT_RELSZ] == tags[DT_JMPREL], "contiguous relocations")
    ck(tags[DT_PLTRELSZ] == 8, "DT_PLTRELSZ preserved")
    ck(tags[DT_RELCOUNT] == 184 + 184 + 7, "DT_RELCOUNT exact")

    # 5. Verify imdb_raw symbol points to expanded table and descriptor 112 has exact fields.
    syms = {s["name"]: s for s in new_view.dynsym_symbols()}
    new_va = int(syms["imdb_raw"]["st_value"])
    ck(new_va == report["raw_linked_va"], "imdb_raw st_value updated")
    desc_va = new_va + 132 + 112 * 44
    words = struct.unpack("<11I", new_view.read_va(desc_va, 44))
    ck(words[:4] == (0x20000003, 4, 1, 0xFFFE), "descriptor header words")
    for idx, expected_str in enumerate(DEFAULT_STRINGS):
        ptr = words[4 + idx]
        raw_s = new_view.read_va(ptr, len(expected_str) + 1)
        ck(raw_s == expected_str.encode("ascii") + b"\x00", f"string {idx}")

    # 6. Verify surrounding descriptors (111 and 113) preserved order & module IDs.
    d111 = struct.unpack("<11I", new_view.read_va(new_va + 132 + 111 * 44, 44))
    d113 = struct.unpack("<11I", new_view.read_va(new_va + 132 + 113 * 44, 44))
    d184 = struct.unpack("<11I", new_view.read_va(new_va + 132 + 184 * 44, 44))
    ck(d111[3] == 0x0100 + 111, "prior descriptor 111 preserved")
    ck(d113[0] == 7 and d113[3] == 0x0100 + 112, "group 7 shifted cleanly to 113")
    ck(d184[0] == 40 and d184[3] == 0x0100 + 183, "sentinel group 40 at 184")

    # 7. Re-running on already-extended image fails closed (0xfffe collision).
    try:
        transform_imdb(out, allow_synthetic=True, expected_count=185)
        raise AssertionError("Expected duplicate module_id rejection")
    except ValueError:
        checks += 1

    print(json.dumps({"passed": True, "test": "imdb_synthetic", "checks": checks}))


if __name__ == "__main__":
    main()
