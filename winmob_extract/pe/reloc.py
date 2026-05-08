"""Synthesize a PE base-relocation directory for a ROM-stripped XIP module.

The pass is approximate - the original .reloc was deleted by romimage,
and any 4-byte aligned value in [vbase, vbase + image_size) could be a
real pointer or a coincidental constant. Best-effort only; only used in
heuristic-reconstruction mode.

Top-level entry point:
    synthesize_reloc(sections, ce_dds, vbase, imgflags) -> (data, rva)
        Mutates `sections` and `ce_dds[5]` in place.
"""

import struct

from ..util import align


# ── Exclude builder ─────────────────────────────────────────────────────────

def _build_excludes(sections, ce_dds):
    """Return [(start_rva, end_rva), ...] of regions that look like
    image-range pointers but are PE metadata, not absolute pointers:
    export name/ordinal tables, import descriptor RVA fields,
    resource directory, debug directory, IAT."""
    exclude = []

    def _sec_data_at(rva):
        for s in sections:
            if s['data'] and s['rva'] <= rva < s['rva'] + len(s['data']):
                return s['data'], rva - s['rva']
        return None, 0

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

    # Resource (DD[2]) and Debug (DD[6]) entries are pure RVAs / file
    # offsets - exclude. Exception/pdata (DD[3]) holds absolute
    # BeginAddress fields under this ABI and does need reloc - not excluded.
    for dd_i in (2, 6):
        if dd_i < len(ce_dds):
            dd_rva, dd_sz = ce_dds[dd_i]
            if dd_rva and dd_sz:
                exclude.append((dd_rva, dd_rva + dd_sz))

    if len(ce_dds) > 7:
        iat_rva, iat_sz = ce_dds[7]
        if iat_rva and iat_sz:
            exclude.append((iat_rva, iat_rva + iat_sz))

    return exclude


# ── Scanner ─────────────────────────────────────────────────────────────────

def _find_reloc_rvas(sections, ce_dds, img_lo, img_end, exclude):
    """Walk every section; record RVAs of 4-byte values that fall in
    [img_lo, img_end). Honours `exclude`. `img_lo` is `vbase + first_section_rva`
    so values pointing into the PE header region are not flagged."""
    pdata_rva, pdata_sz = ce_dds[3] if len(ce_dds) > 3 else (0, 0)
    rsrc_rva, rsrc_sz = ce_dds[2] if len(ce_dds) > 2 else (0, 0)

    def _is_rsrc_section(sec):
        if not (rsrc_rva and rsrc_sz):
            return False
        sec_end = sec['rva'] + max(sec['vsize'], len(sec['data']))
        return sec['rva'] <= rsrc_rva < sec_end

    def _in_exclude(rva):
        for start, end in exclude:
            if start <= rva < end:
                return True
        return False

    rvas = []
    for sec in sections:
        if not sec['data'] or sec['name'].startswith(b'.reloc'):
            continue
        if not (sec['flags'] & 0x20) and _is_rsrc_section(sec):
            continue
        # .pdata stride 8: each entry is (BeginAddress, flags+length);
        # only BeginAddress is a real pointer.
        stride = 4
        if (pdata_rva and pdata_sz and
            sec['rva'] <= pdata_rva < sec['rva'] + max(sec['vsize'], len(sec['data']))):
            stride = 8
        for off in range(0, len(sec['data']) - 3, stride):
            val = struct.unpack_from('<I', sec['data'], off)[0]
            if img_lo <= val < img_end:
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
            entries.append(0)  # 4-byte alignment padding
        block_sz = 8 + len(entries) * 2
        out += struct.pack('<II', page, block_sz)
        for e in entries:
            out += struct.pack('<H', e)
    return bytes(out)


# ── Public API ──────────────────────────────────────────────────────────────

def _is_valid_reloc_blob(data, max_sz):
    """Do these bytes parse as PE base-relocation blocks? Used to detect
    a stale DD[5] pointer whose underlying bytes were stripped."""
    if len(data) < 12:
        return False
    p = 0
    blocks_ok = 0
    while p + 8 <= len(data) and p < max_sz:
        page = struct.unpack_from('<I', data, p)[0]
        blk = struct.unpack_from('<I', data, p + 4)[0]
        if blk == 0:
            break
        if page & 0xFFF:
            return False
        if blk < 8 or (blk & 1) or blk > max_sz - p:
            return False
        n = (blk - 8) // 2
        for i in range(n):
            if p + 8 + i * 2 + 2 > len(data):
                return False
            w = struct.unpack_from('<H', data, p + 8 + i * 2)[0]
            if (w >> 12) > 10:
                return False
        blocks_ok += 1
        p += blk
    return blocks_ok > 0


def _existing_reloc_valid(sections, ce_dds):
    """True iff ce_dds[5] points into a section whose bytes parse as
    a valid reloc table."""
    rel_rva, rel_sz = ce_dds[5]
    if not (rel_rva and rel_sz):
        return False
    for sec in sections:
        if not sec.get('data'):
            continue
        sec_end = sec['rva'] + len(sec['data'])
        if sec['rva'] <= rel_rva < sec_end:
            off = rel_rva - sec['rva']
            return _is_valid_reloc_blob(sec['data'][off:off + rel_sz], rel_sz)
    return False


def synthesize_reloc(sections, ce_dds, vbase, imgflags=0):
    """Build a synthetic .reloc directory. Mutates `sections` and
    `ce_dds[5]` in place. Returns (reloc_data, reloc_rva); both empty
    when no synth is needed.

    Skips when imgflags has IMAGE_FILE_RELOCS_STRIPPED (CE EXEs) or when
    the ROM preserved a valid .reloc table at DD[5]. When DD[5] points at
    stripped bytes, drops the stale section and rebuilds.
    """
    if imgflags & 0x0001:
        return b'', 0
    if _existing_reloc_valid(sections, ce_dds):
        return b'', 0
    sections[:] = [s for s in sections if not s.get('name', b'').startswith(b'.reloc')]
    ce_dds[5] = (0, 0)

    SA = 0x1000
    size_of_image = align(max(s['rva'] + s['vsize'] for s in sections), SA)
    img_end = min(vbase + size_of_image, 0x100000000)

    img_lo = vbase
    if any(s['data'] for s in sections):
        first_sec_rva = min(s['rva'] for s in sections if s['data'])
        img_lo = vbase + first_sec_rva

    exclude = _build_excludes(sections, ce_dds)

    reloc_rvas = _find_reloc_rvas(sections, ce_dds, img_lo, img_end, exclude)
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
