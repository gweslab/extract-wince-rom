"""Parsers for ROMHDR-referenced CE structures used to enrich rom_meta:
the ROMPID extension chain, the per-module e32_rom header, the per-module
o32_rom section records, and the ROMHDR copy table. These read metadata the
region extractor records into rom_meta.json; they do not drive PE emission.
"""

import base64
import struct

from .util import read_ascii
from .pe.e32 import parse_e32_auto


def _hex(v):
    return f"0x{v & 0xFFFFFFFF:08X}"


def _hex16(v):
    return f"0x{v & 0xFFFF:04X}"


def parse_rompid_chain(data, load_offset, head_va):
    """Walk a ROMPID extension linked list starting at head_va. Returns a
    list of dicts ready for rom_meta.json's `rompid` field. Empty list when
    head_va is 0 or the chain doesn't parse.

    Layout assumed (per CE conventions): each ROMPID node has
        type        : DWORD
        pNextExt    : DWORD (VA of next, 0 = end)
        pdata       : DWORD (VA of data blob)
        length      : DWORD (data length)
        pszName     : DWORD (VA of ASCII name string)
    Total 20 bytes. Inline-name layouts (no pszName VA) are not handled
    here; the chain bails on the first node that produces inconsistent
    values rather than emit garbage.
    """
    chain = []
    seen = set()
    node_va = head_va
    while node_va and node_va not in seen and len(chain) < 64:
        seen.add(node_va)
        node_off = node_va - load_offset
        if not (0 <= node_off and node_off + 20 <= len(data)):
            break
        type_, next_va, pdata_va, length, name_va = \
            struct.unpack_from('<5I', data, node_off)
        # Sanity gate: length should be reasonable
        if length > 0x10000000:
            break
        # Treat all-zero / placeholder nodes as "no extension". Real
        # ROMPID entries have at least a type or a name pointer or a
        # non-zero data length.
        if type_ == 0 and length == 0 and name_va == 0 and pdata_va == 0:
            break
        # Decode name if pointer is plausible
        name = ''
        if 0 < name_va:
            name_off = name_va - load_offset
            if 0 <= name_off < len(data) - 1:
                name = read_ascii(data, name_off)
        # Decode data blob if pointer is plausible
        data_b64 = ''
        if length and 0 < pdata_va:
            pdata_off = pdata_va - load_offset
            if 0 <= pdata_off and pdata_off + length <= len(data):
                data_b64 = base64.b64encode(
                    data[pdata_off:pdata_off + length]).decode('ascii')
        chain.append({
            'name': name,
            'type': type_,
            'data_b64': data_b64,
            'length': length,
        })
        node_va = next_va
    return chain


def parse_e32_header(data, load_offset, e32_va):
    """Read e32_rom fields needed for rom_meta module entries: image size,
    entry RVA, image base, subsystem, subsystem version, timestamp, image
    flags, object count. Tries the extended layout first (4-byte timestamp
    field at +0x20 + DD array at +0x24) and falls back to legacy (DD array
    at +0x20, no timestamp field) when extended fails validity checks.
    Returns dict or None if the e32 header isn't readable.
    """
    info, _ = parse_e32_auto(data, e32_va - load_offset)
    return info


def parse_section_records(data, load_offset, o32_va, objcnt):
    """Read `objcnt` o32_rom records (24 bytes each) starting at VA `o32_va`.

    Each record exposes {vsize, rva, psize, dataptr, realaddr, flags}. CE
    splits between `rva` (link-time RVA) and `realaddr` (runtime VA the
    kernel maps the section to via MMU): they differ for sections that
    live in ROM but are mapped to RAM at runtime, and for sections whose
    runtime address differs from `vbase + rva`. PE reconstruction
    flattens both into the on-disk PE, so the original split is only
    recoverable from these records.
    """
    if not o32_va or not objcnt or objcnt > 64:
        return []
    base_off = o32_va - load_offset
    if base_off < 0 or base_off + objcnt * 24 > len(data):
        return []
    out = []
    for s in range(objcnt):
        sv, sr, sp, sd, sa, sf = struct.unpack_from('<6I', data, base_off + s * 24)
        out.append({
            'vsize':    _hex(sv),
            'rva':      _hex(sr),
            'psize':    _hex(sp),
            'dataptr':  _hex(sd),
            'realaddr': _hex(sa),
            'flags':    _hex(sf),
        })
    return out


def parse_copy_table(data, load_offset, copy_va, n_entries):
    """Parse the ROMHDR copy table at `copy_va` (n_entries x 16 bytes).

    Each COPYentry is { ulSource, ulDest, ulCopyLen, ulDestLen }: copy
    `ulCopyLen` bytes src->dst, then zero-fill the remaining
    `ulDestLen - ulCopyLen` bytes at dst+ulCopyLen. The kernel runs this
    pass early in startup (CE5+ sub_80095584) to materialise .data/.bss
    in RAM before any /GS-protected code runs.
    """
    if not copy_va or not n_entries or n_entries > 4096:
        return []
    base_off = copy_va - load_offset
    if base_off < 0 or base_off + n_entries * 16 > len(data):
        return []
    out = []
    for i in range(n_entries):
        src, dst, cl, dl = struct.unpack_from('<4I', data, base_off + i * 16)
        out.append({
            'src':      _hex(src),
            'dst':      _hex(dst),
            'copy_len': _hex(cl),
            'dest_len': _hex(dl),
        })
    return out
