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
        # When raw_size in ROM exceeds vsize, the bytes beyond vsize are
        # whatever follows the section in ROM (often the next module's
        # e32/o32 records). The source PE pads that gap with zeros - mirror
        # that so the emitted PE tail bytes match.
        if not (sf & 0x2000) and len(data) > sv:
            data = data[:sv] + b'\x00' * (len(data) - sv)
        sections.append(dict(
            name=section_name(sf, sr, ce_dds, vsize=sv),
            vsize=sv, rva=sr, raw_size=len(data) if data else sp,
            flags=sf, data=data))
        if sa != 0 and sa != vbase + sr:
            realaddr_map.append((sr, sa, sv))
    return sections, realaddr_map


def _resolve_section_overlaps(sections, ce_dds):
    """Some modules have two o32 records sharing the same RVA (e.g. a
    writable .data section and a read-only .pdata section overlaid),
    because at runtime they live at different physical addresses (one
    in RAM, one XIP). For an on-disk PE the sections must be at distinct
    RVAs - shift each later section up to the next SectionAlignment-
    aligned slot after the previous one ends, and update any data
    directory that pointed at the old RVA."""
    SA = 0x1000
    sections.sort(key=lambda s: s['rva'])
    for i in range(1, len(sections)):
        prev = sections[i - 1]
        cur = sections[i]
        prev_end = prev['rva'] + max(prev['vsize'], prev['raw_size'])
        prev_end_aligned = (prev_end + SA - 1) & ~(SA - 1)
        if cur['rva'] < prev_end_aligned:
            old_rva = cur['rva']
            cur['rva'] = prev_end_aligned
            for j in range(len(ce_dds)):
                ddr, dds = ce_dds[j]
                if ddr == old_rva and dds == cur['vsize']:
                    ce_dds[j] = (cur['rva'], dds)


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


def reconstruct_pe_xip(flat, base_off, e32_va, o32_va, machine=0x01C0,
                       dd_offset=None, heuristic=False):
    """Build PE from XIP module (separate e32/o32 pointers in flat image).

    Returns (pe_data, has_shared_rva). `has_shared_rva` is True when two or
    more o32_rom records share the same `rva` - CE allows this (a writable
    RAM-mapped section and a read-only ROM-mapped section overlaid at the
    same link-time slot, never live simultaneously) but PE format forbids
    it (section table requires distinct VirtualAddresses). For those
    modules we skip the RVA-shifting fixup so the PE preserves the
    original o32.rva values - the PE is technically PE-spec invalid (IDA
    and Ghidra parse it, the Windows PE loader rejects), but bytes are
    byte-faithful and the original layout is recoverable. Callers route
    these to a separate output location.

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
        return None, False
    n = info['objcnt']
    if o32 < 0 or o32 + n * O32_SIZE > len(flat):
        return None, False

    vbase = info['vbase']
    ce_dds = list(info['ce_dds'])  # mutable copy
    imgflags = info['imgflags']

    sections, realaddr_map = _read_xip_sections(flat, base_off, o32, n,
                                                info['ce_dds'], vbase)
    _add_dd_sections(flat, base_off, sections, ce_dds, vbase)
    rvas = [s['rva'] for s in sections]
    has_shared_rva = len(set(rvas)) != len(rvas)
    if not has_shared_rva:
        _resolve_section_overlaps(sections, ce_dds)
    else:
        # Preserve original RVAs; just sort so the section table is in
        # rva order (PE convention, even when RVAs collide).
        sections.sort(key=lambda s: s['rva'])
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

    sections.sort(key=lambda s: s['rva'])

    pe_data = build_pe(n, imgflags, info['entry_rva'], vbase,
                       info['sub_maj'], info['sub_min'], info['stackmax'],
                       info['vsize'], info['timestamp'], ce_dds,
                       sections, machine, info.get('subsystem', 9),
                       info.get('sect14_rva', 0), info.get('sect14_size', 0))
    if not pe_data:
        return None, has_shared_rva
    # IAT directory metadata (DD[12]) is always populated; only the byte
    # rewrite (bound -> unbound) is gated on heuristic mode.
    pe_data = fix_iat_from_ilt(pe_data, rewrite_iat=heuristic)
    if heuristic:
        pe_data = unrebase_dll(pe_data,
                               reloc_is_ground_truth=reloc_is_ground_truth)
    return pe_data, has_shared_rva


def reconstruct_pe_imgfs(header_data, section_data_map, heuristic=False):
    """Build PE from IMGFS module (combined e32rom+o32_rom header blob).

    Returns (pe_data, has_shared_rva) - same shared-RVA semantics as
    reconstruct_pe_xip. Always uses the extended e32rom layout. IMGFS
    typically preserves source PE .reloc bytes as a stored section, so
    DD[5] often stays populated even in raw mode.
    """
    if not header_data or len(header_data) < 0x70:
        return None, False
    info = parse_e32_base(header_data, 0, E32_DD_OFF_WM5)
    if info is None:
        return None, False
    n = info['objcnt']
    if len(header_data) < 0x70 + n * O32_SIZE:
        return None, False

    ce_dds = list(info['ce_dds'])
    imgflags = info['imgflags']

    sections = []
    for s in range(n):
        so = 0x70 + s * O32_SIZE
        sv, sr, sp, sd, sa, sf = struct.unpack_from('<6I', header_data, so)
        key = f'S{s:03d}'
        data = section_data_map.get(key, b'')
        sections.append(dict(
            name=section_name(sf, sr, ce_dds, vsize=sv),
            vsize=sv, rva=sr, raw_size=len(data) if data else sp,
            flags=sf, data=data))

    rvas = [s['rva'] for s in sections]
    has_shared_rva = len(set(rvas)) != len(rvas)

    reloc_is_ground_truth = _existing_reloc_valid(sections, ce_dds)

    if not heuristic and not reloc_is_ground_truth:
        sections[:] = [s for s in sections
                       if not s.get('name', b'').startswith(b'.reloc')]
        ce_dds[5] = (0, 0)
        imgflags |= 0x0001  # IMAGE_FILE_RELOCS_STRIPPED

    pe_data = build_pe(n, imgflags, info['entry_rva'], info['vbase'],
                       info['sub_maj'], info['sub_min'], info['stackmax'],
                       info['vsize'], info['timestamp'], ce_dds,
                       sections, subsystem=info.get('subsystem', 9),
                       sect14_rva=info.get('sect14_rva', 0),
                       sect14_size=info.get('sect14_size', 0))
    if not pe_data:
        return None, has_shared_rva
    pe_data = fix_iat_from_ilt(pe_data, rewrite_iat=heuristic)
    if heuristic:
        pe_data = unrebase_dll(pe_data,
                               reloc_is_ground_truth=reloc_is_ground_truth)
    return pe_data, has_shared_rva
