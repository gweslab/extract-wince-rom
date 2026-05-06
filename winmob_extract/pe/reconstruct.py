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
from .reloc import synthesize_reloc


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
            name=section_name(sf, sr, ce_dds),
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


def reconstruct_pe_xip(flat, base_off, e32_va, o32_va, machine=0x01C0,
                       dd_offset=None):
    """Build PE from XIP module (separate e32/o32 pointers in flat image).

    Auto-detects e32rom layout (legacy/WM2003 vs WM5+) unless dd_offset is
    explicitly given.
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

    sections, realaddr_map = _read_xip_sections(flat, base_off, o32, n,
                                                info['ce_dds'], vbase)
    _add_dd_sections(flat, base_off, sections, ce_dds, vbase)
    _patch_realaddr_refs(sections, realaddr_map, vbase)
    synthesize_reloc(sections, ce_dds, vbase)

    sections.sort(key=lambda s: s['rva'])

    pe_data = build_pe(n, info['imgflags'], info['entry_rva'], vbase,
                       info['sub_maj'], info['sub_min'], info['stackmax'],
                       info['vsize'], info['timestamp'], ce_dds,
                       sections, machine, info.get('subsystem', 9),
                       info.get('sect14_rva', 0), info.get('sect14_size', 0))
    return fix_iat_from_ilt(pe_data) if pe_data else None


def reconstruct_pe_imgfs(header_data, section_data_map):
    """Build PE from IMGFS module (combined e32rom+o32_rom header blob).

    IMGFS modules always use the WM5+-style e32rom layout.
    """
    if not header_data or len(header_data) < 0x70:
        return None
    info = parse_e32_base(header_data, 0, E32_DD_OFF_WM5)
    if info is None:
        return None
    n = info['objcnt']
    if len(header_data) < 0x70 + n * O32_SIZE:
        return None

    sections = []
    for s in range(n):
        so = 0x70 + s * O32_SIZE
        sv, sr, sp, sd, sa, sf = struct.unpack_from('<6I', header_data, so)
        key = f'S{s:03d}'
        data = section_data_map.get(key, b'')
        sections.append(dict(
            name=section_name(sf, sr, info['ce_dds']),
            vsize=sv, rva=sr, raw_size=len(data) if data else sp,
            flags=sf, data=data))

    pe_data = build_pe(n, info['imgflags'], info['entry_rva'], info['vbase'],
                       info['sub_maj'], info['sub_min'], info['stackmax'],
                       info['vsize'], info['timestamp'], info['ce_dds'],
                       sections, subsystem=info.get('subsystem', 9),
                       sect14_rva=info.get('sect14_rva', 0),
                       sect14_size=info.get('sect14_size', 0))
    return fix_iat_from_ilt(pe_data) if pe_data else None
