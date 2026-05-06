"""Synthesize a PE base-relocation directory for an XIP module.

The ROM builder strips the original .reloc directory (XIP modules don't
need it at load time, since they run at a fixed VA). To produce a PE
that can be loaded at any base, we reconstruct .reloc by scanning the
section bytes for 4-byte values that look like absolute references to
something in the module's image range.

This pass is inherently approximate — there is no ground truth. False
positives have shipped multiple times (resource sentinels, ARM instruction
encodings). See README.md for the full caveat.

Top-level entry point:
    synthesize_reloc(sections, ce_dds, vbase) -> (reloc_data, reloc_rva)
        Mutates `sections` in place: appends a .reloc section if any
        relocations were found. Mutates `ce_dds[5]` to point at it.
        Returns (b'', 0) when there are no relocations.

The scanner is split into three passes:
  1. ARM/Thumb LDR-PC literal pools inside .text
  2. Gaps between functions in .text (per .pdata) - data interleaved with code
  3. Whole-section scan in writable / non-resource data sections

Low-base modules (vbase < size_of_image) get an exclude list of RVA-based
PE structures (export name table, import descriptors, IAT, etc.) whose
small offsets coincidentally fall in the image range.
"""

import struct

from ..util import align


# ── Scanners ────────────────────────────────────────────────────────────────

def _find_literal_pool_offsets(text_data):
    """Scan .text for ARM/Thumb LDR [PC, #offset] instructions and return
    the set of literal pool data offsets (byte offsets within text_data)."""
    pool = set()
    sz = len(text_data)
    # ARM mode: 4-byte aligned LDR Rd, [PC, #offset]
    for i in range(0, sz - 3, 4):
        instr = struct.unpack_from('<I', text_data, i)[0]
        if (instr & 0x0F7F0000) == 0x051F0000:
            off12 = instr & 0xFFF
            addr = i + 8 + off12 if (instr >> 23) & 1 else i + 8 - off12
            if 0 <= addr <= sz - 4 and (addr & 3) == 0:
                pool.add(addr)
    # Thumb mode: 2-byte aligned
    for i in range(0, sz - 1, 2):
        hw = struct.unpack_from('<H', text_data, i)[0]
        # Thumb 16-bit: LDR Rd, [PC, #imm8*4]
        if (hw & 0xF800) == 0x4800:
            addr = ((i + 4) & ~3) + (hw & 0xFF) * 4
            if 0 <= addr <= sz - 4 and (addr & 3) == 0:
                pool.add(addr)
        # Thumb-2 32-bit: LDR.W Rd, [PC, #imm12]
        elif (hw & 0xFF7F) == 0xF85F and i + 3 < sz:
            hw2 = struct.unpack_from('<H', text_data, i + 2)[0]
            off12 = hw2 & 0xFFF
            base = (i + 4) & ~3
            addr = base + off12 if (hw >> 7) & 1 else base - off12
            if 0 <= addr <= sz - 4 and (addr & 3) == 0:
                pool.add(addr)
    return pool


def _get_code_ranges(sections, vbase, pdata_rva, pdata_sz, text_rva, text_vsize):
    """Parse .pdata to get sorted (start, end) code ranges within .text."""
    ranges = []
    for sec in sections:
        if sec['data'] and sec['rva'] <= pdata_rva < sec['rva'] + len(sec['data']):
            base = pdata_rva - sec['rva']
            for i in range(pdata_sz // 8):
                eo = base + i * 8
                if eo + 8 > len(sec['data']):
                    break
                begin_rva = struct.unpack_from('<I', sec['data'], eo)[0]
                flags = struct.unpack_from('<I', sec['data'], eo + 4)[0]
                func_len = (flags >> 8) & 0x3FFFFF
                insn_sz = 4 if (flags >> 30) & 1 else 2
                fs = begin_rva - vbase - text_rva
                fe = fs + func_len * insn_sz
                if 0 <= fs < text_vsize:
                    ranges.append((fs, min(fe, text_vsize)))
            break
    ranges.sort()
    return ranges


def _is_in_code(off, code_ranges):
    """Binary search: is byte offset `off` inside any (start, end) range?"""
    lo, hi = 0, len(code_ranges) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        s, e = code_ranges[mid]
        if off < s:
            hi = mid - 1
        elif off >= e:
            lo = mid + 1
        else:
            return True
    return False


# ── Exclude builder for low-base modules ────────────────────────────────────

def _build_excludes(sections, ce_dds):
    """Return [(start_rva, end_rva), ...] of RVAs that look like image-range
    pointers but are actually fields of PE metadata (export name table,
    import descriptors, IAT, etc.). Only relevant for low-base modules
    (vbase < size_of_image) where these small RVAs collide with image VAs."""
    exclude = []

    def _sec_data_at(rva):
        for s in sections:
            if s['data'] and s['rva'] <= rva < s['rva'] + len(s['data']):
                return s['data'], rva - s['rva']
        return None, 0

    # Export directory (DD[0]): exclude header + name tables, NOT function table
    exp_rva, exp_sz = ce_dds[0] if len(ce_dds) > 0 else (0, 0)
    if exp_rva and exp_sz:
        exclude.append((exp_rva, exp_rva + 40))  # IMAGE_EXPORT_DIRECTORY header
        d, off = _sec_data_at(exp_rva)
        if d and off + 40 <= len(d):
            names_rva = struct.unpack_from('<I', d, off + 32)[0]
            ords_rva  = struct.unpack_from('<I', d, off + 36)[0]
            num_names = struct.unpack_from('<I', d, off + 24)[0]
            if names_rva:
                exclude.append((names_rva, names_rva + num_names * 4))
            if ords_rva:
                exclude.append((ords_rva, ords_rva + num_names * 2))

    # Import directory (DD[1]): exclude descriptor array + ILT regions
    imp_rva, imp_sz = ce_dds[1] if len(ce_dds) > 1 else (0, 0)
    if imp_rva and imp_sz:
        exclude.append((imp_rva, imp_rva + imp_sz))
        d, off = _sec_data_at(imp_rva)
        if d:
            pos = off
            while pos + 20 <= len(d):
                ilt_rva = struct.unpack_from('<I', d, pos)[0]
                iat_rva = struct.unpack_from('<I', d, pos + 16)[0]
                if ilt_rva == 0 and iat_rva == 0:
                    break
                if ilt_rva:
                    d2, off2 = _sec_data_at(ilt_rva)
                    if d2:
                        end2 = off2
                        while end2 + 4 <= len(d2):
                            if struct.unpack_from('<I', d2, end2)[0] == 0:
                                end2 += 4; break
                            end2 += 4
                        exclude.append((ilt_rva, ilt_rva + (end2 - off2)))
                pos += 20

    # Resource (DD[2]), Exception/pdata (DD[3]), Debug (DD[6]): all RVA-based
    for dd_i in (2, 3, 6):
        if dd_i < len(ce_dds):
            dd_rva, dd_sz = ce_dds[dd_i]
            if dd_rva and dd_sz:
                exclude.append((dd_rva, dd_rva + dd_sz))

    # IAT (CE DD[7] -> PE DD[12]): ordinal hints after IAT fix
    if len(ce_dds) > 7:
        iat_rva, iat_sz = ce_dds[7]
        if iat_rva and iat_sz:
            exclude.append((iat_rva, iat_rva + iat_sz))

    return exclude


# ── Main scanner: find absolute references in section bytes ─────────────────

def _find_reloc_rvas(sections, ce_dds, vbase, img_end, exclude):
    """Walk every section; for each 4-byte value that falls in [vbase, img_end),
    record its RVA as needing a base-relocation entry. Honours `exclude`."""
    pdata_rva, pdata_sz = ce_dds[3] if len(ce_dds) > 3 else (0, 0)
    rsrc_rva, rsrc_sz = ce_dds[2] if len(ce_dds) > 2 else (0, 0)

    def _is_rsrc_section(sec):
        if rsrc_rva and rsrc_sz:
            sec_end = sec['rva'] + max(sec['vsize'], len(sec['data']))
            if sec['rva'] <= rsrc_rva < sec_end:
                return True
        return False

    def _in_exclude(rva):
        for start, end in exclude:
            if start <= rva < end:
                return True
        return False

    rvas = []
    for sec in sections:
        if not sec['data'] or sec['name'].startswith(b'.reloc'):
            continue
        if sec['flags'] & 0x20:
            # Code section: LDR pools (within functions) + pdata gaps (between functions)
            ldr_offsets = _find_literal_pool_offsets(sec['data'])
            pdata_offsets = set()
            if pdata_rva and pdata_sz:
                code_ranges = _get_code_ranges(sections, vbase, pdata_rva, pdata_sz,
                                               sec['rva'], sec['vsize'])
                if code_ranges:
                    for off in range(0, len(sec['data']) - 3, 4):
                        if not _is_in_code(off, code_ranges):
                            val = struct.unpack_from('<I', sec['data'], off)[0]
                            if vbase <= val < img_end:
                                pdata_offsets.add(off)
            for off in sorted(ldr_offsets | pdata_offsets):
                val = struct.unpack_from('<I', sec['data'], off)[0]
                if vbase <= val < img_end:
                    abs_rva = sec['rva'] + off
                    if not _in_exclude(abs_rva):
                        rvas.append(abs_rva)
        else:
            # Skip resource section (identified by IMAGE_DIRECTORY_ENTRY_RESOURCE)
            if _is_rsrc_section(sec):
                continue
            # Data sections: scan all 4-byte aligned values
            for off in range(0, len(sec['data']) - 3, 4):
                val = struct.unpack_from('<I', sec['data'], off)[0]
                if vbase <= val < img_end:
                    abs_rva = sec['rva'] + off
                    if not _in_exclude(abs_rva):
                        rvas.append(abs_rva)
    return rvas


def _build_reloc_blocks(reloc_rvas):
    """Format sorted reloc_rvas as PE base-relocation block bytes.
    Each block: u32 page_rva, u32 block_size, then u16 entries
    (type<<12 | offset). Type 3 = IMAGE_REL_BASED_HIGHLOW."""
    out = bytearray()
    i = 0
    while i < len(reloc_rvas):
        page = reloc_rvas[i] & ~0xFFF
        entries = []
        while i < len(reloc_rvas) and (reloc_rvas[i] & ~0xFFF) == page:
            entries.append((3 << 12) | (reloc_rvas[i] & 0xFFF))
            i += 1
        if len(entries) & 1:
            entries.append(0)  # padding to align block to 4 bytes
        block_sz = 8 + len(entries) * 2
        out += struct.pack('<II', page, block_sz)
        for e in entries:
            out += struct.pack('<H', e)
    return bytes(out)


# ── Public API ──────────────────────────────────────────────────────────────

def synthesize_reloc(sections, ce_dds, vbase):
    """Build a PE base-relocation directory for the given module.

    Mutates `sections` in place: appends a .reloc section if any relocations
    were found. Mutates `ce_dds[5]` to point at it.

    Returns (reloc_data, reloc_rva); both empty when no relocations exist.
    """
    SA = 0x1000
    size_of_image = align(max(s['rva'] + s['vsize'] for s in sections), SA)
    # Saturate image end at 32-bit boundary to prevent wrap-around for high-base modules
    img_end = min(vbase + size_of_image, 0x100000000)

    # Build exclude ranges only for low-base modules where RVAs can collide
    # with image VAs. High-base modules can't have such collisions.
    exclude = _build_excludes(sections, ce_dds) if vbase < size_of_image else []

    reloc_rvas = _find_reloc_rvas(sections, ce_dds, vbase, img_end, exclude)
    if not reloc_rvas:
        return b'', 0

    reloc_rvas.sort()
    reloc_data = _build_reloc_blocks(reloc_rvas)

    max_rva = max(s['rva'] + max(s['vsize'], s['raw_size']) for s in sections)
    reloc_rva = align(max_rva, SA)
    sections.append(dict(
        name=b'.reloc\x00\x00',
        vsize=len(reloc_data),
        rva=reloc_rva,
        raw_size=len(reloc_data),
        flags=0x42000040,  # INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ
        data=reloc_data))
    ce_dds[5] = (reloc_rva, len(reloc_data))
    return reloc_data, reloc_rva
