"""Un-rebase a DLL from its ROM-baked vbase to the canonical 0x10000000
ImageBase by walking DD[5] and subtracting (vbase - 0x10000000) at each
HIGHLOW position. Heuristic-mode only.
"""

import struct


CANONICAL_DLL_BASE = 0x10000000


def unrebase_dll(pe_data, reloc_is_ground_truth=False):
    """Rewrite a DLL's ImageBase to CANONICAL_DLL_BASE.

    No-op when chars has RELOCS_STRIPPED, the PE is not a DLL, ImageBase
    is already canonical, or DD[5] is empty. The value-range gate
    (only rewrite a target whose current value is in [vbase, vbase+imgsz))
    protects against IAT entries whose absolute pointers have already
    been converted to RVA hints.
    """
    if not pe_data or len(pe_data) < 0x80:
        return pe_data
    pe = bytearray(pe_data)
    pe_off = struct.unpack_from('<I', pe, 0x3C)[0]
    if pe_off + 24 > len(pe) or pe[pe_off:pe_off + 4] != b'PE\x00\x00':
        return pe_data
    chars = struct.unpack_from('<H', pe, pe_off + 22)[0]
    if chars & 0x0001:                      # RELOCS_STRIPPED
        return pe_data
    if not (chars & 0x2000):                # not a DLL
        return pe_data

    o = pe_off + 24
    cur_base = struct.unpack_from('<I', pe, o + 28)[0]
    if cur_base == CANONICAL_DLL_BASE:
        return pe_data

    rel_rva = struct.unpack_from('<I', pe, o + 96 + 5 * 8)[0]
    rel_sz  = struct.unpack_from('<I', pe, o + 100 + 5 * 8)[0]
    if not rel_rva or not rel_sz:
        return pe_data

    img_size = struct.unpack_from('<I', pe, o + 56)[0]
    img_lo = cur_base
    img_hi = cur_base + img_size

    nsec = struct.unpack_from('<H', pe, pe_off + 6)[0]
    ohsz = struct.unpack_from('<H', pe, pe_off + 20)[0]
    sec_off = pe_off + 24 + ohsz
    sec_map = []
    for i in range(nsec):
        h = sec_off + i * 40
        s_vsize, s_rva, s_rawsz, s_rawptr = struct.unpack_from('<IIII', pe, h + 8)
        sec_map.append((s_rva, max(s_vsize, s_rawsz), s_rawptr))

    def rva_to_off(rva):
        for s_rva, s_sz, s_off in sec_map:
            if s_rva <= rva < s_rva + s_sz:
                return s_off + (rva - s_rva)
        return None

    rel_off = rva_to_off(rel_rva)
    if rel_off is None:
        return pe_data

    delta = (CANONICAL_DLL_BASE - cur_base) & 0xFFFFFFFF

    p = rel_off
    end = rel_off + rel_sz
    while p < end:
        page = struct.unpack_from('<I', pe, p)[0]
        blk  = struct.unpack_from('<I', pe, p + 4)[0]
        if blk == 0 or blk > rel_sz - (p - rel_off):
            break
        n = (blk - 8) // 2
        for i in range(n):
            w = struct.unpack_from('<H', pe, p + 8 + i * 2)[0]
            if w >> 12 != 3:  # HIGHLOW only
                continue
            target_off = rva_to_off(page + (w & 0xFFF))
            if target_off is None or target_off + 4 > len(pe):
                continue
            val = struct.unpack_from('<I', pe, target_off)[0]
            if img_lo <= val < img_hi:
                struct.pack_into('<I', pe, target_off, (val + delta) & 0xFFFFFFFF)
        p += blk

    struct.pack_into('<I', pe, o + 28, CANONICAL_DLL_BASE)
    return bytes(pe)
