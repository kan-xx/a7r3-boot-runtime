#!/usr/bin/env python3
"""Data-only libIMDB.so PT_LOAD module-registry transformer (zero code edits).

Appends an aligned PT_LOAD data region expanding Sony A7R III (FW 3.10)
libIMDB.so's 44-byte module descriptor table from 184 -> 185 records by
inserting module_id=0xfffe (group=6, load_mask=4, target_mask=1) at index 112
(immediately before group 7).

Key invariants enforced:
  1. 100% of original SHF_EXECINSTR executable sections (.init, .plt, .text,
     .fini) and .rel.plt / .ARM.attributes remain byte-for-byte identical.
  2. DT_REL + DT_RELSZ == DT_JMPREL (contiguous relocation tables), avoiding
     glibc ld-2.11.2.so's DT_BIND_NOW non-contiguous DT_RELCOUNT corruption bug.
  3. All 184 stock descriptors and their R_ARM_RELATIVE pointers are preserved
     in original order.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

STOCK_IMDB_SHA256 = "0f4d6355c0f8903714f8af506da7c4d357c9d66ed725fbc9f344fe82c928a321"
EXPECTED_ADDON_SHA256 = "f2620309212756f6e59d008796a38931e18ac352bf2f1c74d9bafe5f65d8e23b"

PT_LOAD = 1
SHT_NOBITS = 8
SHT_REL = 9
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
R_ARM_RELATIVE = 23

DT_PLTRELSZ = 2
DT_REL = 17
DT_RELSZ = 18
DT_JMPREL = 23
DT_RELCOUNT = 0x6FFFFFFA

DEFAULT_STRINGS = [
    "/usr/lib/liba7r_startup_full_v14.so",
    "A7R_Lifecycle_Init",
    "A7R_Lifecycle_Exit",
    "A7R_Lifecycle_Sus",
    "A7R_Lifecycle_Res",
    "A7R_Lifecycle_Inact",
    "A7R_Lifecycle_Act",
]


class Elf32View:
    """Minimal dependency-free 32-bit little-endian ARM ELF parser."""

    def __init__(self, raw: bytes | bytearray):
        self.raw = bytes(raw)
        if len(self.raw) < 52 or self.raw[:4] != b"\x7fELF" or self.raw[4] != 1 or self.raw[5] != 1:
            raise ValueError("Expected 32-bit little-endian ELF image")
        (
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        ) = struct.unpack_from("<HHIIIIIHHHHHH", self.raw, 16)
        if self.e_phentsize != 32 or self.e_shentsize != 40:
            raise ValueError("Unexpected ELF32 header entry size")

        self.phdrs: list[dict[str, int]] = []
        for i in range(self.e_phnum):
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = (
                struct.unpack_from("<8I", self.raw, self.e_phoff + i * 32)
            )
            self.phdrs.append(
                {
                    "index": i,
                    "p_type": p_type,
                    "p_offset": p_offset,
                    "p_vaddr": p_vaddr,
                    "p_paddr": p_paddr,
                    "p_filesz": p_filesz,
                    "p_memsz": p_memsz,
                    "p_flags": p_flags,
                    "p_align": p_align,
                }
            )

        self.shdrs: list[dict[str, int | str]] = []
        for i in range(self.e_shnum):
            (
                sh_name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            ) = struct.unpack_from("<10I", self.raw, self.e_shoff + i * 40)
            self.shdrs.append(
                {
                    "index": i,
                    "sh_name_off": sh_name,
                    "sh_type": sh_type,
                    "sh_flags": sh_flags,
                    "sh_addr": sh_addr,
                    "sh_offset": sh_offset,
                    "sh_size": sh_size,
                    "sh_link": sh_link,
                    "sh_info": sh_info,
                    "sh_addralign": sh_addralign,
                    "sh_entsize": sh_entsize,
                    "name": "",
                }
            )

        shstr = self.section_bytes(self.e_shstrndx)
        for sec in self.shdrs:
            off = int(sec["sh_name_off"])
            end = shstr.find(b"\x00", off)
            sec["name"] = shstr[off:end].decode("ascii", errors="replace") if end >= 0 else ""

    def section_bytes(self, idx: int) -> bytes:
        sec = self.shdrs[idx]
        if sec["sh_type"] == SHT_NOBITS:
            return b""
        off = int(sec["sh_offset"])
        sz = int(sec["sh_size"])
        return self.raw[off : off + sz]

    def section_by_name(self, name: str) -> dict[str, int | str]:
        for sec in self.shdrs:
            if sec["name"] == name:
                return sec
        raise KeyError(f"Missing ELF section: {name}")

    def read_va(self, va: int, size: int) -> bytes:
        for ph in self.phdrs:
            if ph["p_type"] == PT_LOAD:
                p_va = ph["p_vaddr"]
                p_off = ph["p_offset"]
                p_fsz = ph["p_filesz"]
                if p_va <= va and va + size <= p_va + p_fsz:
                    start = p_off + (va - p_va)
                    return self.raw[start : start + size]
        raise ValueError(f"VA range {va:#x}..{va + size:#x} not backed by PT_LOAD file bytes")

    def word_va(self, va: int) -> int:
        return struct.unpack("<I", self.read_va(va, 4))[0]

    def dynsym_symbols(self) -> list[dict[str, int | str]]:
        ds = self.section_by_name(".dynsym")
        dynstr_sec = self.shdrs[int(ds["sh_link"])]
        dynstr = self.section_bytes(int(dynstr_sec["index"]))
        data = self.section_bytes(int(ds["index"]))
        out: list[dict[str, int | str]] = []
        for i in range(0, len(data), 16):
            st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                "<IIIBBH", data, i
            )
            end = dynstr.find(b"\x00", st_name)
            name = dynstr[st_name:end].decode("ascii", errors="replace") if end >= 0 else ""
            out.append(
                {
                    "index": i // 16,
                    "name": name,
                    "st_value": st_value,
                    "st_size": st_size,
                    "st_info": st_info,
                    "st_other": st_other,
                    "st_shndx": st_shndx,
                }
            )
        return out

    def relocations(self, sec_name: str) -> list[tuple[int, int, int]]:
        sec = self.section_by_name(sec_name)
        data = self.section_bytes(int(sec["index"]))
        out: list[tuple[int, int, int]] = []
        for i in range(0, len(data), 8):
            r_offset, r_info = struct.unpack_from("<II", data, i)
            out.append((r_offset, r_info & 0xFF, r_info >> 8))
        return out

    def dynamic_tags(self) -> list[tuple[int, int, int]]:
        sec = self.section_by_name(".dynamic")
        data = self.section_bytes(int(sec["index"]))
        out: list[tuple[int, int, int]] = []
        for i in range(0, len(data), 8):
            d_tag, d_val = struct.unpack_from("<II", data, i)
            out.append((i // 8, d_tag, d_val))
            if d_tag == 0:
                break
        return out


def transform_imdb(
    stock_bytes: bytes,
    *,
    allow_synthetic: bool = False,
    strings: list[str] | None = None,
    module_id: int = 0xFFFE,
    insert_index: int = 112,
    expected_count: int = 184,
) -> tuple[bytes, dict]:
    """Return (extended_elf_bytes, metadata_dict) without modifying executable sections."""
    stock_sha = hashlib.sha256(stock_bytes).hexdigest()
    skip_fw_sha = allow_synthetic or os.environ.get("A7R3_SKIP_FW_SHA256") == "1"
    if not skip_fw_sha and stock_sha != STOCK_IMDB_SHA256:
        raise ValueError(
            f"Stock libIMDB.so SHA-256 mismatch: got {stock_sha}, expected {STOCK_IMDB_SHA256}"
        )

    strings = list(DEFAULT_STRINGS if strings is None else strings)
    if len(strings) != 7:
        raise ValueError("Expected 7 descriptor strings (DSO path + 6 lifecycle symbols)")

    e = Elf32View(stock_bytes)
    syms = {s["name"]: s for s in e.dynsym_symbols()}
    if "imdb_raw" not in syms:
        raise ValueError("Missing exported symbol 'imdb_raw' in .dynsym")

    old_va = int(syms["imdb_raw"]["st_value"])
    table_va = old_va + 132
    if e.word_va(table_va + insert_index * 44) != 7:
        raise ValueError("Expected group 7 boundary at insert_index")
    if e.word_va(table_va + (expected_count - 1) * 44) != 40:
        raise ValueError("Expected group 40 sentinel at final descriptor")
    for i in range(expected_count):
        if (e.word_va(table_va + i * 44 + 12) & 0xFFFF) == module_id:
            raise ValueError(f"Module ID {module_id:#x} already exists at index {i}")

    b = bytearray(stock_bytes)
    oldsec = bytes(b[e.e_shoff : e.e_shoff + e.e_shnum * 40])
    loads = [ph for ph in e.phdrs if ph["p_type"] == PT_LOAD]
    if not loads:
        raise ValueError("No PT_LOAD segments found")
    last = loads[-1]
    pi = last["index"]
    delta = last["p_vaddr"] - last["p_offset"]
    if not allow_synthetic and delta != 32768:
        raise ValueError(f"Unexpected RW PT_LOAD vaddr-offset delta: {delta}")

    # Preserve zero-filled BSS bytes when growing the final RW PT_LOAD past EOF.
    zero_start = last["p_offset"] + last["p_filesz"]
    zero_end = last["p_offset"] + last["p_memsz"]
    b[zero_start:zero_end] = bytes(zero_end - zero_start)

    moved_sections: dict[int, int] = {}
    for sec in e.shdrs:
        idx = int(sec["index"])
        sh_off = int(sec["sh_offset"])
        sh_sz = int(sec["sh_size"])
        if sec["sh_type"] != SHT_NOBITS and sh_sz and sh_off < zero_end and sh_off + sh_sz > zero_start:
            if int(sec["sh_flags"]) & SHF_ALLOC:
                raise ValueError(f"Allocated section {sec['name']} overlaps BSS tail")
            align = max(1, int(sec["sh_addralign"]))
            b += bytes((-len(b)) % align)
            moved_sections[idx] = len(b)
            b += e.section_bytes(idx)

    b += bytes((-len(b)) % 16)
    new_off = len(b)
    new_va = new_off + delta

    blob = (
        bytearray(e.read_va(old_va, 132 + 44 * insert_index))
        + bytearray(44)
        + bytearray(e.read_va(table_va + 44 * insert_index, 44 * (expected_count - insert_index)))
    )
    ptrs: list[int] = []
    for s in strings:
        ptrs.append(new_va + len(blob))
        blob += s.encode("ascii") + b"\x00"

    new_desc = new_va + 132 + 44 * insert_index
    struct.pack_into("<11I", blob, 132 + 44 * insert_index, 0x20000003, 4, 1, module_id, *ptrs)
    blob += bytes((-len(blob)) % 4)
    b += blob

    orig_rel: list[tuple[int, int]] = []
    new_rel: list[tuple[int, int]] = []
    for r_off, r_type, r_sym in e.relocations(".rel.dyn"):
        orig_rel.append((r_off, (r_sym << 8) | r_type))
        if old_va <= r_off < table_va + 44 * expected_count:
            if r_type != R_ARM_RELATIVE or r_sym != 0:
                raise ValueError("Unexpected non-relative relocation inside imdb_raw table")
            shift = 44 if r_off >= table_va + 44 * insert_index else 0
            new_rel.append((new_va + (r_off - old_va) + shift, R_ARM_RELATIVE))
    new_rel.extend((new_desc + 16 + 4 * i, R_ARM_RELATIVE) for i in range(7))

    rels = (
        [x for x in orig_rel if (x[1] & 0xFF) == R_ARM_RELATIVE]
        + new_rel
        + [x for x in orig_rel if (x[1] & 0xFF) != R_ARM_RELATIVE]
    )
    if len({addr for addr, _ in rels}) != len(rels):
        raise ValueError("Duplicate relocation target address")

    rel_off = len(b)
    rel_va = rel_off + delta
    b += b"".join(struct.pack("<II", addr, info) for addr, info in rels)

    plt_off = len(b)
    plt_va = plt_off + delta
    plt_sec = e.section_by_name(".rel.plt")
    plt_data = e.section_bytes(int(plt_sec["index"]))
    b += plt_data

    dyn_sec = e.section_by_name(".dynamic")
    dyn_off = int(dyn_sec["sh_offset"])
    rel_count = sum((x[1] & 0xFF) == R_ARM_RELATIVE for x in rels)
    tag_updates = {
        DT_REL: rel_va,
        DT_RELSZ: len(rels) * 8,
        DT_RELCOUNT: rel_count,
        DT_JMPREL: plt_va,
    }
    for idx, d_tag, _ in e.dynamic_tags():
        if d_tag in tag_updates:
            struct.pack_into("<I", b, dyn_off + 8 * idx + 4, tag_updates[d_tag])

    ds_sec = e.section_by_name(".dynsym")
    ds_off = int(ds_sec["sh_offset"])
    new_sec_index = e.e_shnum
    for sym in e.dynsym_symbols():
        if sym["name"] == "imdb_raw":
            i = int(sym["index"])
            struct.pack_into("<I", b, ds_off + 16 * i + 4, new_va)
            struct.pack_into("<H", b, ds_off + 16 * i + 14, new_sec_index)

    names = bytearray(e.section_bytes(e.e_shstrndx))
    nameoff = len(names)
    names += b".a7r.imdb\x00"
    names_off = len(b)
    b += names
    b += bytes((-len(b)) % 4)

    shoff = len(b)
    headers = bytearray(oldsec)
    for sec in e.shdrs:
        i = int(sec["index"])
        if i in moved_sections:
            struct.pack_into("<I", headers, i * 40 + 16, moved_sections[i])
        if sec["name"] == ".rel.dyn":
            struct.pack_into("<III", headers, i * 40 + 12, rel_va, rel_off, len(rels) * 8)
        if sec["name"] == ".rel.plt":
            struct.pack_into("<III", headers, i * 40 + 12, plt_va, plt_off, len(plt_data))
        if i == e.e_shstrndx:
            struct.pack_into("<II", headers, i * 40 + 16, names_off, len(names))

    headers += struct.pack("<10I", nameoff, 1, 3, new_va, new_off, len(blob), 0, 0, 4, 0)
    b += headers

    struct.pack_into("<I", b, 32, shoff)
    struct.pack_into("<H", b, 48, e.e_shnum + 1)
    new_seg_sz = len(b) - last["p_offset"]
    struct.pack_into("<II", b, e.e_phoff + pi * 32 + 16, new_seg_sz, new_seg_sz)

    # Self-audit: 100% of executable sections & PLT/attributes must be unchanged.
    for sec in e.shdrs:
        if int(sec["sh_flags"]) & SHF_EXECINSTR:
            off = int(sec["sh_offset"])
            sz = int(sec["sh_size"])
            if bytes(b[off : off + sz]) != e.section_bytes(int(sec["index"])):
                raise AssertionError(f"Executable section mutated: {sec['name']}")

    out_bytes = bytes(b)
    check = Elf32View(out_bytes)
    dtags = {tag: val for _, tag, val in check.dynamic_tags()}
    if dtags[DT_REL] + dtags[DT_RELSZ] != dtags[DT_JMPREL]:
        raise AssertionError("DT_REL and DT_JMPREL are not contiguous")
    if dtags[DT_PLTRELSZ] != len(plt_data):
        raise AssertionError("DT_PLTRELSZ mismatch")
    if check.section_bytes(int(check.section_by_name(".rel.plt")["index"])) != plt_data:
        raise AssertionError(".rel.plt bytes mutated")
    try:
        orig_attr = e.section_bytes(int(e.section_by_name(".ARM.attributes")["index"]))
        new_attr = check.section_bytes(int(check.section_by_name(".ARM.attributes")["index"]))
        if orig_attr != new_attr:
            raise AssertionError(".ARM.attributes mutated")
    except KeyError:
        if not allow_synthetic:
            raise

    out_sha = hashlib.sha256(out_bytes).hexdigest()
    if not skip_fw_sha and strings == DEFAULT_STRINGS and out_sha != EXPECTED_ADDON_SHA256:
        raise AssertionError(
            f"Deterministic output SHA-256 mismatch: got {out_sha}, expected {EXPECTED_ADDON_SHA256}"
        )

    report = {
        "original_sha256": stock_sha,
        "candidate_sha256": out_sha,
        "bytes": len(out_bytes),
        "module_id": module_id,
        "group": 6,
        "load_mask": 4,
        "target_mask": 1,
        "insert_index": insert_index,
        "record_count": expected_count + 1,
        "raw_linked_va": new_va,
        "descriptor_linked_va": new_desc,
        "strings": strings,
        "original_code_unchanged": True,
        "original_record_order_preserved": True,
        "relocations": len(rels),
        "relative_relocations": rel_count,
    }
    return out_bytes, report


def default_stock_imdb_path(fw_root: str | None) -> Path | None:
    root = fw_root or os.environ.get("A7R3_FW_ROOT")
    if not root:
        return None
    return Path(root) / "nflasha15/export/lib/libIMDB.so"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fw-root",
        help="Path to extracted firmware filesystems root (or set A7R3_FW_ROOT)",
    )
    parser.add_argument(
        "--stock-imdb",
        type=Path,
        help="Explicit path to stock FW 3.10 libIMDB.so (overrides --fw-root)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output path for extended data-only libIMDB.so",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Optional output path for JSON transformation report",
    )
    parser.add_argument(
        "--dso-path",
        default=DEFAULT_STRINGS[0],
        help=f"Target coordinator DSO path in descriptor[4] (default: {DEFAULT_STRINGS[0]})",
    )
    parser.add_argument(
        "--allow-synthetic",
        action="store_true",
        help="Allow synthetic/custom ELF inputs rather than enforcing stock FW 3.10 SHA-256",
    )
    args = parser.parse_args()

    stock_path = args.stock_imdb or default_stock_imdb_path(args.fw_root)
    if stock_path is None:
        parser.error("Provide --stock-imdb or --fw-root / A7R3_FW_ROOT")

    custom_strings = [args.dso_path, *DEFAULT_STRINGS[1:]]
    out_bytes, report = transform_imdb(
        stock_path.read_bytes(),
        allow_synthetic=args.allow_synthetic,
        strings=custom_strings,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(out_bytes)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
