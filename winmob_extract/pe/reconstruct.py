"""Module reconstruction: orchestrate e32rom decode + PE assembly.

Two flavours of XIP module:
  - reconstruct_pe_xip:   modules in a flat ROM image (.BIN B000FF, .nb0).
                          o32_rom records sit alongside the e32rom in the image.
  - reconstruct_pe_imgfs: modules stored in IMGFS (NB0 .DLLs, .EXEs etc.).
                          Each section's bytes are passed in section_data_map;
                          the e32rom + o32_rom array is in `header_data`.
"""

import struct

from ..util import align
from ..compress import ce_rom_decompress
from .build import build_pe, section_name
from .e32 import (parse_e32_base, parse_e32_auto, O32_SIZE,
                  E32_DD_OFF_LEGACY, E32_DD_OFF_WM5)
from .cerom import (CEROM_SECTION_FLAGS, CEROM_SECTION_NAME,
                    build_cerom_blob, pick_primary_indices)
from .iat import fix_iat_from_ilt
from .rebase import unrebase_dll
from .reloc import synthesize_reloc, _existing_reloc_valid


_DD_NAMES_SHORT = ['.edata', '.idata', '.rsrc', '.pdata', '.certs',
                   '.reloc', '.debug', '.imd', '.msp']


def _read_xip_sections(flat, base_off, o32, n, ce_dds, vbase):
    """Decode `n` o32_rom entries starting at flat-offset `o32`. Return
    (sections, realaddr_map) where realaddr_map tracks split-address sections
    (those whose o32_realaddr differs from vbase + rva)."""
    sections = []
    realaddr_map = []
    for s in range(n):
        so = o32 + s * O32_SIZE
        sv, sr, sp, sd, sa, sf = struct.unpack_from('<6I', flat, so)
        data = b''
        if sp > 0 and sd >= base_off:
            d = sd - base_off
            if 0 <= d and d + sp <= len(flat):
                data = bytes(flat[d:d + sp])
                # Decompress if section is compressed (CE flag 0x2000)
                if (sf & 0x2000) and sp < sv and data:
                    dec = ce_rom_decompress(data, sv)
                    if len(dec) == sv:
                        data = dec
        sections.append(dict(
            name=section_name(sf, sr, ce_dds, vsize=sv),
            vsize=sv, rva=sr, raw_size=len(data) if data else sp,
            flags=sf, data=data))
        if sa != 0 and sa != vbase + sr:
            realaddr_map.append((sr, sa, sv))
    return sections, realaddr_map


def _add_dd_sections(flat, base_off, sections, ce_dds, vbase):
    """For each non-zero data directory not covered by an existing section,
    fetch its bytes from the flat image and add as a synthetic section.
    If the bytes aren't available, clear the DD entry so PE tools don't
    crash trying to follow a dangling pointer."""
    SA = 0x1000
    for dd_i in range(len(ce_dds)):
        dd_rva, dd_sz = ce_dds[dd_i]
        if dd_rva == 0 or dd_sz == 0:
            continue
        covered = False
        for sec in sections:
            if sec['rva'] <= dd_rva < sec['rva'] + max(sec['vsize'], sec['raw_size']):
                covered = True
                break
        if covered:
            continue
        dd_va = vbase + dd_rva
        dd_flat = dd_va - base_off
        if 0 <= dd_flat and dd_flat + dd_sz <= len(flat):
            dd_data = bytes(flat[dd_flat:dd_flat + dd_sz])
            sec_rva = align(dd_rva, SA)
            if dd_rva % SA != 0:
                pad = dd_rva - sec_rva
                dd_data = b'\x00' * pad + dd_data
                sec_rva = dd_rva - pad
            sname = _DD_NAMES_SHORT[dd_i] if dd_i < len(_DD_NAMES_SHORT) else f'.dd{dd_i}'
            sections.append(dict(
                name=sname.encode('ascii').ljust(8, b'\x00')[:8],
                vsize=align(len(dd_data), SA),
                rva=sec_rva,
                raw_size=len(dd_data),
                flags=0x40000040,  # INITIALIZED_DATA | MEM_READ
                data=dd_data))
        else:
            ce_dds[dd_i] = (0, 0)


def _patch_realaddr_refs(sections, realaddr_map, vbase):
    """Step 1 of .reloc synthesis: rewrite split-address pointers to PE-space.

    A 'split-address' data section has its bytes shipped at vbase+rva (in ROM)
    but is mapped at o32_realaddr (in RAM) at runtime. References inside the
    section that point to other locations within the same section have been
    pre-baked to the realaddr range; we translate them back to the PE address."""
    if not realaddr_map:
        return
    for sec in sections:
        if not sec['data']:
            continue
        buf = bytearray(sec['data'])
        for off in range(0, len(buf) - 3, 4):
            val = struct.unpack_from('<I', buf, off)[0]
            for sec_rva, real_addr, sz in realaddr_map:
                if real_addr <= val < real_addr + sz:
                    new_val = vbase + sec_rva + (val - real_addr)
                    struct.pack_into('<I', buf, off, new_val)
                    break
        sec['data'] = bytes(buf)
        sec['raw_size'] = len(sec['data'])


def _extraction_state(o32_records):
    """Return (flags_after_extraction, psize_after_extraction) per record.
    Decompressed sections get IMAGE_SCN_COMPRESSED cleared and psize=vsize;
    others pass through unchanged."""
    out = []
    for sv, sr, sp, sd, sa, sf in o32_records:
        if (sf & 0x2000) and sp < sv:
            out.append((sf & ~0x2000, sv))
        else:
            out.append((sf, sp))
    return out


def _append_cerom_section(sections, cerom_blob):
    """Append a `.cerom` section past the highest existing section.

    SizeOfImage in the PE OptionalHeader will grow to cover it; the
    original e32.vsize is preserved inside `.cerom`'s TOC field so a CE
    consumer can still read the pre-extension image size.
    """
    SA = 0x1000
    sections.sort(key=lambda s: s['rva'])
    if sections:
        last = sections[-1]
        end = last['rva'] + max(last['vsize'], last['raw_size'])
        cerom_rva = (end + SA - 1) & ~(SA - 1)
    else:
        cerom_rva = SA
    sections.append(dict(
        name=CEROM_SECTION_NAME,
        vsize=len(cerom_blob),
        rva=cerom_rva,
        raw_size=len(cerom_blob),
        flags=CEROM_SECTION_FLAGS,
        data=cerom_blob,
    ))


def reconstruct_pe_xip(flat, base_off, e32_va, o32_va, machine=0x01C0,
                       dd_offset=None, heuristic=False, toc_dict=None):
    """Build PE from XIP module (separate e32/o32 pointers in flat image).

    The emitted PE is always PE-spec valid - shared-RVA collisions
    (CE's romimage allows two o32_rom records at the same rva, PE format
    forbids two section headers at the same VirtualAddress) are resolved
    by emitting one o32 record per rva-group in the standard PE section
    table; the other records in the group become "shadow" entries in
    the appended `.cerom` section, with their bytes embedded inside it.
    A CE kernel emulator (or any other tool that needs the full
    o32_rom set + per-section runtime layout `realaddr` / `dataptr`)
    reads `.cerom`; standard PE tools (IDA, Ghidra, objdump, the
    Windows PE loader) ignore it and see a normal PE.

    `toc_dict` carries TOCentry-derived fields to embed in `.cerom`:
    e32_offset, o32_offset, name_offset, load_va, file_size, attributes,
    filetime_lo, filetime_hi. Pass None for callers without TOC info.

    Default (raw) emits bytes verbatim, ImageBase=vbase, IAT bound,
    RELOCS_STRIPPED set when no reloc table preserved.
    `heuristic=True` enables synth .reloc + un-rebase to 0x10000000 + IAT
    unbinding; the synth pass has structural FPs that can corrupt embedded
    constants and is not recommended for production.
    """
    e32 = e32_va - base_off
    o32 = o32_va - base_off
    if dd_offset is None:
        info, _ = parse_e32_auto(flat, e32)
    else:
        info = parse_e32_base(flat, e32, dd_offset)
    if info is None:
        return None
    n = info['objcnt']
    if o32 < 0 or o32 + n * O32_SIZE > len(flat):
        return None

    vbase = info['vbase']
    ce_dds = list(info['ce_dds'])  # mutable copy
    imgflags = info['imgflags']

    # Snapshot every o32_rom record up-front (full 6-tuple) so .cerom can
    # carry the complete set even after we drop shadows from the PE
    # section list.
    o32_records = [
        struct.unpack_from('<6I', flat, o32 + s * O32_SIZE) for s in range(n)
    ]
    primary_indices = pick_primary_indices(o32_records)

    # Decide whether this module needs `.cerom` at all. PE format can
    # encode every CE module that has unique rvas AND no split-address
    # sections (realaddr == 0 or realaddr == vbase+rva for every o32);
    # those modules emit a clean PE with no extension. .cerom is only
    # appended for modules where PE genuinely can't carry the layout.
    has_shared_rva = len(set(o[1] for o in o32_records)) != len(o32_records)
    has_split_addr = any(
        sa != 0 and sa != vbase + sr
        for sv, sr, sp, sd, sa, sf in o32_records
    )
    needs_cerom = has_shared_rva or has_split_addr

    sections, realaddr_map = _read_xip_sections(flat, base_off, o32, n,
                                                info['ce_dds'], vbase)
    _add_dd_sections(flat, base_off, sections, ce_dds, vbase)

    # Drop shadow sections from the visible PE section table. The first
    # `n` entries in `sections` correspond to o32_records by index;
    # entries past `n` are synthetic data-directory sections added by
    # _add_dd_sections and stay regardless.
    pe_sections = [sections[i] for i in range(n) if i in primary_indices]
    pe_sections.extend(sections[n:])
    sections = pe_sections

    if heuristic:
        _patch_realaddr_refs(sections, realaddr_map, vbase)

    # Did the ROM preserve the original .reloc bytes?
    reloc_is_ground_truth = _existing_reloc_valid(sections, ce_dds)

    if heuristic:
        synthesize_reloc(sections, ce_dds, vbase, imgflags)
    elif not reloc_is_ground_truth:
        # Raw mode + no ground-truth reloc: drop any stale .reloc section
        # _add_dd_sections may have synthesized, clear DD[5], and mark
        # the PE as RELOCS_STRIPPED so loaders fail loud rather than
        # apply an empty reloc table.
        sections[:] = [s for s in sections
                       if not s.get('name', b'').startswith(b'.reloc')]
        ce_dds[5] = (0, 0)
        imgflags |= 0x0001  # IMAGE_FILE_RELOCS_STRIPPED

    # `.cerom` is always emitted so per-module TOCentry data
    # (e32_offset, o32_offset, name_offset, load_va, attributes, ...) is
    # reachable from the PE container alone. For pure modules (no
    # shared-RVA, no split-address) the section carries only the header
    # + TOC block (n_objects == 0); o32_rom records and shadow bytes are
    # added only when PE format actually fails to describe the layout.
    toc = dict(toc_dict or {})
    toc.setdefault('e32_vsize', info['vsize'])
    if needs_cerom:
        def get_shadow_bytes(i):
            sv, sr, sp, sd, sa, sf = o32_records[i]
            if sp == 0:
                return b''
            d = sd - base_off
            if d < 0 or d + sp > len(flat):
                return b''
            data = bytes(flat[d:d + sp])
            if (sf & 0x2000) and sp < sv and data:
                dec = ce_rom_decompress(data, sv)
                if len(dec) == sv:
                    data = dec
            return data

        cerom_blob = build_cerom_blob(o32_records, _extraction_state(o32_records),
                                      primary_indices, toc, get_shadow_bytes)
    else:
        cerom_blob = build_cerom_blob([], [], set(), toc, lambda i: b'')
    _append_cerom_section(sections, cerom_blob)

    sections.sort(key=lambda s: s['rva'])

    pe_data = build_pe(len(sections), imgflags, info['entry_rva'], vbase,
                       info['sub_maj'], info['sub_min'], info['stackmax'],
                       info['vsize'], info['timestamp'], ce_dds,
                       sections, machine, info.get('subsystem', 9),
                       info.get('sect14_rva', 0), info.get('sect14_size', 0))
    if not pe_data:
        return None
    # IAT directory metadata (DD[12]) is always populated; only the byte
    # rewrite (bound -> unbound) is gated on heuristic mode.
    pe_data = fix_iat_from_ilt(pe_data, rewrite_iat=heuristic)
    if heuristic:
        pe_data = unrebase_dll(pe_data,
                               reloc_is_ground_truth=reloc_is_ground_truth)
    return pe_data


def reconstruct_pe_imgfs(header_data, section_data_map, heuristic=False,
                         toc_dict=None):
    """Build PE from IMGFS module (combined e32rom+o32_rom header blob).

    Same `.cerom`-based shared-RVA handling as reconstruct_pe_xip: the
    standard PE section table gets one entry per rva-group, the rest
    become shadows in `.cerom` with their bytes embedded. Always uses
    the extended e32rom layout. IMGFS typically preserves source PE
    .reloc bytes as a stored section, so DD[5] often stays populated
    even in raw mode.

    `toc_dict` is optional and typically all-zero except for `e32_vsize`
    (IMGFS modules have no TOCentry). Pass None to default to all-zero.
    """
    if not header_data or len(header_data) < 0x70:
        return None
    info = parse_e32_base(header_data, 0, E32_DD_OFF_WM5)
    if info is None:
        return None
    n = info['objcnt']
    if len(header_data) < 0x70 + n * O32_SIZE:
        return None

    ce_dds = list(info['ce_dds'])
    imgflags = info['imgflags']

    vbase = info['vbase']
    o32_records = []
    section_bytes_map = {}  # idx -> bytes
    for s in range(n):
        so = 0x70 + s * O32_SIZE
        rec = struct.unpack_from('<6I', header_data, so)
        o32_records.append(rec)
        key = f'S{s:03d}'
        section_bytes_map[s] = section_data_map.get(key, b'')

    primary_indices = pick_primary_indices(o32_records)

    has_shared_rva = len(set(o[1] for o in o32_records)) != len(o32_records)
    has_split_addr = any(
        sa != 0 and sa != vbase + sr
        for sv, sr, sp, sd, sa, sf in o32_records
    )
    needs_cerom = has_shared_rva or has_split_addr

    sections = []
    for i, (sv, sr, sp, sd, sa, sf) in enumerate(o32_records):
        if i not in primary_indices:
            continue
        data = section_bytes_map[i]
        sections.append(dict(
            name=section_name(sf, sr, ce_dds, vsize=sv),
            vsize=sv, rva=sr, raw_size=len(data) if data else sp,
            flags=sf, data=data))

    reloc_is_ground_truth = _existing_reloc_valid(sections, ce_dds)

    if not heuristic and not reloc_is_ground_truth:
        sections[:] = [s for s in sections
                       if not s.get('name', b'').startswith(b'.reloc')]
        ce_dds[5] = (0, 0)
        imgflags |= 0x0001  # IMAGE_FILE_RELOCS_STRIPPED

    toc = dict(toc_dict or {})
    toc.setdefault('e32_vsize', info['vsize'])
    if needs_cerom:
        cerom_blob = build_cerom_blob(o32_records, _extraction_state(o32_records),
                                      primary_indices, toc,
                                      lambda i: section_bytes_map.get(i, b''))
    else:
        cerom_blob = build_cerom_blob([], [], set(), toc, lambda i: b'')
    _append_cerom_section(sections, cerom_blob)

    sections.sort(key=lambda s: s['rva'])

    pe_data = build_pe(len(sections), imgflags, info['entry_rva'], info['vbase'],
                       info['sub_maj'], info['sub_min'], info['stackmax'],
                       info['vsize'], info['timestamp'], ce_dds,
                       sections, subsystem=info.get('subsystem', 9),
                       sect14_rva=info.get('sect14_rva', 0),
                       sect14_size=info.get('sect14_size', 0))
    if not pe_data:
        return None
    pe_data = fix_iat_from_ilt(pe_data, rewrite_iat=heuristic)
    if heuristic:
        pe_data = unrebase_dll(pe_data,
                               reloc_is_ground_truth=reloc_is_ground_truth)
    return pe_data
