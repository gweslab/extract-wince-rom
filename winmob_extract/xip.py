"""XIP region extraction: locate ECEC signatures, parse ROMHDR + TOC, emit
PE files for each module and verbatim copies for non-module files.

The ECEC marker (signature 'CECE' little-endian) sits at physfirst+0x40
per romldr.h, followed by ROM_TOC_POINTER_OFFSET (+0x44) and
ROM_TOC_OFFSET_OFFSET (+0x48). Pre-CE5 ROMs only define the signature
slot; +4/+8 may be unused or used as an undocumented convenience.
"""

import os
import struct

from .util import (u32, read_ascii, safe_filename,
                   ROMHDR_SIZE, TOCENTRY_SIZE, FILEENTRY_SIZE)
from .compress import ce_rom_decompress
from .machine import resolve_machine
from .pe import reconstruct_pe_xip
from .rom_structs import (_hex, _hex16, parse_rompid_chain,
                          parse_e32_header, parse_section_records,
                          parse_copy_table)


def find_all_ecec(data, limit=None):
    """Find all ECEC signatures that look like valid XIP region markers.

    Returns a list of (ecec_offset, ptoc_va, romhdr_offset). The last two
    fields come from u32 reads at ECEC+4 and ECEC+8."""
    results = []
    end = limit if limit else len(data)
    pos = 0
    while pos < end - 12:
        idx = data.find(b'ECEC', pos)
        if idx == -1 or idx >= end:
            break
        if idx + 12 <= len(data):
            ptoc_va = u32(data, idx + 4)
            romhdr_off = u32(data, idx + 8)
            # ECEC+8 (ROM_TOC_OFFSET_OFFSET) is a CE5+ convenience. Pre-CE5
            # ROMs (CE3 / HPC2000 / WM2003) leave it unused - commonly
            # 0xFFFFFFFF from erased flash. Treat any out-of-range value as
            # absent (0) rather than disqualifying the ECEC: detection keys on
            # ptoc_va, and the extractor derives the load base from it when
            # romhdr_off is 0 (see the candidate list in extract_xip_regions).
            if not (0 <= romhdr_off < 0x10000000):
                romhdr_off = 0
            # VA should be in CE kernel range
            if 0x80000000 <= ptoc_va < 0xC0000000:
                results.append((idx, ptoc_va, romhdr_off))
        pos = idx + 4
    return results


def find_romhdr_structural(data):
    """Locate the ROMHDR when there is no ECEC marker (CE 2.x ROMs - the
    ECEC signature slot was added in CE3 romldr.h). Slide a validating
    window and confirm the TOC resolves printable module names including
    nk.exe, matching CERF rom_image_parse.cpp ResolveRomhdrStructural.

    Returns (romhdr_off, load_offset, ptoc_va) or None. load_offset is the
    XIP base such that file_offset == VA - load_offset; for a carved XIP
    region that is physfirst.
    """
    n = len(data)
    for off in range(0, n - ROMHDR_SIZE, 4):
        # Cheap prefilter: physfirst is a CE kernel VA and physlast a
        # sane distance above it. Rejects almost every offset before the
        # full parse.
        physfirst = u32(data, off + 8)
        if physfirst < 0x80000000:
            continue
        physlast = u32(data, off + 12)
        if not (physfirst < physlast <= physfirst + 0x10000000):
            continue
        hdr = parse_romhdr(data, off)
        if hdr is None or not (1 <= hdr['nummods'] <= 4096):
            continue
        load_offset = hdr['physfirst']
        toc_start = off + ROMHDR_SIZE
        names_ok = True
        have_nk = False
        for i in range(min(hdr['nummods'], 32)):
            e = toc_start + i * TOCENTRY_SIZE
            if e + TOCENTRY_SIZE > n:
                names_ok = False
                break
            fname_off = u32(data, e + 0x10) - load_offset
            if not (0 <= fname_off < n - 1):
                names_ok = False
                break
            name = read_ascii(data, fname_off)
            if not name or any(c < 0x20 or c > 0x7E for c in name.encode('latin1', 'replace')):
                names_ok = False
                break
            if name.lower() == 'nk.exe':
                have_nk = True
        if names_ok and have_nk:
            ptoc_va = (load_offset + off) & 0xFFFFFFFF
            return off, load_offset, ptoc_va
    return None


def parse_romhdr(data, off):
    """Parse ROMHDR at the given offset. Returns dict or None."""
    if off < 0 or off + ROMHDR_SIZE > len(data):
        return None
    fields = struct.unpack_from('<17I2HI2I', data, off)
    hdr = dict(
        dllfirst=fields[0], dlllast=fields[1],
        physfirst=fields[2], physlast=fields[3],
        nummods=fields[4],
        ulRAMStart=fields[5], ulRAMFree=fields[6], ulRAMEnd=fields[7],
        ulCopyEntries=fields[8], ulCopyOffset=fields[9],
        ulProfileLen=fields[10], ulProfileOffset=fields[11],
        numfiles=fields[12],
        ulKernelFlags=fields[13], ulFSRamPercent=fields[14],
        ulDrivglobStart=fields[15], ulDrivglobLen=fields[16],
        usCPUType=fields[17], usMiscFlags=fields[18],
        pExtensions=fields[19],
        ulTrackingStart=fields[20], ulTrackingLen=fields[21],
    )
    # Validation (from loadbin_nb0.cpp FindROMHDRFromAddress)
    if hdr['dllfirst'] > hdr['dlllast']:
        return None
    if hdr['physfirst'] > hdr['physlast']:
        return None
    if hdr['nummods'] > 10000 or hdr['numfiles'] > 50000:
        return None
    return hdr


def _derive_base_from_ptoc(data, ptoc_va):
    """Derive (romhdr_off, load_offset) for a region whose load base is not
    supplied externally (an NB0 region image run from RAM: the file is the
    region itself, with no container header to carry the base).

    The ROMHDR sits at VA ptoc_va, so its file offset is ptoc_va - physfirst.
    physfirst is unknown, but the ROMHDR carries its own physfirst field
    (ROMHDR+8), which closes the loop: the real ROMHDR is the offset `off`
    where physfirst(off) + off == ptoc_va. That fixpoint is the exact
    self-consistency test. Returns (off, physfirst) or None.
    A cheap u32 prefilter rejects almost every offset before the full parse.
    """
    n = len(data)
    for off in range(0, n - ROMHDR_SIZE, 4):
        if (u32(data, off + 8) + off) & 0xFFFFFFFF != ptoc_va:
            continue
        hdr = parse_romhdr(data, off)
        if hdr is not None and 1 <= hdr['nummods'] <= 4096:
            return off, hdr['physfirst']
    return None


def _region_candidates(base_offset, ecec_off, ptoc_va, romhdr_off_field):
    """Build the (romhdr_off, load_offset) candidate list for one ECEC using
    the externally-supplied base. (Self-consistent derivation is a separate
    fallback - see _derive_base_from_ptoc.)"""
    if romhdr_off_field:
        # ECEC+8 holds the ROMHDR offset from physfirst.
        xip_base = max(ecec_off - 0x40, 0)
        romhdr_off = xip_base + romhdr_off_field
        return [(romhdr_off, ptoc_va - romhdr_off)]
    # ECEC+8 zero: try the explicit base_offset, the kernel-VA mirror (some
    # B000FF images carry physical addresses in the section table while ECEC
    # still carries the virtual VA), and high-bit masks of the value at ECEC+4.
    candidates = [(ptoc_va - base_offset, base_offset)]
    mirror = base_offset | 0x80000000
    if mirror != base_offset:
        candidates.append((ptoc_va - mirror, mirror))
    for mask in (0xFF000000, 0xF0000000):
        cand_load = ptoc_va & mask
        cand_off = ptoc_va - cand_load
        if (cand_off, cand_load) not in candidates:
            candidates.append((cand_off, cand_load))
    return candidates


def _resolve_region(data, candidates):
    """Return (hdr, romhdr_off, load_offset) for the first candidate whose
    ROMHDR parses, or (None, None, None)."""
    for romhdr_off, load_offset in candidates:
        if 0 <= romhdr_off and romhdr_off + ROMHDR_SIZE <= len(data):
            h = parse_romhdr(data, romhdr_off)
            if h is not None:
                return h, romhdr_off, load_offset
    return None, None, None


def _region_headers(data, base_offset):
    """Resolve every XIP region in a flat image, writing nothing.

    Returns (regions, structural_off):
      regions:        [(ecec_off, ptoc_va, romhdr_off_field, hdr,
                      romhdr_off, load_offset)], or None when the image
                      carries neither an ECEC marker nor a structurally
                      recoverable ROMHDR.
      structural_off: ROMHDR offset when it came from the structural scan.
    """
    # Scan the whole image for ECEC markers: a multi-XIP ROM places later
    # regions (notably the NK kernel region) in the file tail, far past any
    # front-of-file window. Each ECEC is validated by parsing its ROMHDR, so
    # a stray 'ECEC' byte match that resolves to no header is skipped
    # harmlessly.
    ececs = find_all_ecec(data)
    structural_off = None

    if not ececs:
        # CE 2.x ROMs carry no ECEC marker. Recover the ROMHDR by
        # structural scan, then synthesize the (ecec_off, ptoc_va,
        # romhdr_off_field) triple the loop below consumes: ecec_off=0x40
        # makes xip_base=0 so romhdr_off_field == romhdr_off, and
        # ptoc_va == load_offset+romhdr_off makes load_offset resolve back
        # to physfirst.
        structural = find_romhdr_structural(data)
        if structural is None:
            return None, None
        structural_off, _load_offset, ptoc_va = structural
        ececs = [(0x40, ptoc_va, structural_off)]

    # When no ECEC resolves through the externally-supplied base candidates,
    # the image carries no container base (a RAM-run NB0 bootloader: region VAs
    # are ~0x900xxxxx and the file IS the region). Only then derive each
    # region's base from its ROMHDR self-consistency. The pre-pass gate scopes
    # the derive to images that need it, so the full-image scan never runs on a
    # container ROM that already resolves.
    use_derive = not any(
        _resolve_region(data, _region_candidates(base_offset, e, p, r))[0]
        is not None
        for e, p, r in ececs
    )

    regions = []
    for ecec_off, ptoc_va, romhdr_off_field in ececs:
        candidates = _region_candidates(base_offset, ecec_off, ptoc_va,
                                        romhdr_off_field)
        hdr, romhdr_off, load_offset = _resolve_region(data, candidates)
        if hdr is None and use_derive and not romhdr_off_field:
            derived = _derive_base_from_ptoc(data, ptoc_va)
            if derived:
                romhdr_off, load_offset = derived
                hdr = parse_romhdr(data, romhdr_off)
        if hdr is None:
            continue
        regions.append((ecec_off, ptoc_va, romhdr_off_field, hdr,
                        romhdr_off, load_offset))
    return regions, structural_off


def probe_cpu_types(data, base_offset):
    """usCPUType of every resolvable XIP region, writing nothing."""
    regions, _ = _region_headers(data, base_offset)
    return [r[3]['usCPUType'] for r in regions or []]


def extract_xip_regions(data, base_offset, output_dir, label="", attr_log=None,
                        fs_mode='raw', rom_meta=None, machine_override=None):
    """Find and extract all XIP regions from a flat image.

    data:        flat image bytes
    base_offset: the VA or load base that converts VAs to offsets in data
                 (file_offset = VA - base_offset)
    output_dir:  root output directory
    label:       prefix for log messages
    attr_log:    optional dict; if provided, records the original CE file
                 attribute bits and FILETIME for every emitted module/file as
                 attr_log['\\Windows\\<name>'] = (attrs_int, filetime_u64).
    fs_mode:     'raw' (default) | 'heuristic' | 'no'.
                 'raw': PE reconstruction with bytes verbatim, no synth.
                 'heuristic': adds .reloc synth + un-rebase + IAT unbinding.
                 'no': skip writing PE / file output entirely; rom_meta still
                       populated.
    rom_meta:    optional dict; if provided, populated with ROMHDR fields,
                 module/file inventory, and ptoc/rompid metadata.
    """
    is_heuristic = (fs_mode == 'heuristic')
    skip_fs = (fs_mode == 'no')

    if rom_meta is not None:
        # Public-call robustness: callers may hand us a partial rom_meta
        # (e.g. {'romhdr': None}). The per-region loop appends to these lists
        # unconditionally, so seed the contract keys to avoid a KeyError.
        for _k in ('modules', 'files', 'rompid', 'copy_table'):
            rom_meta.setdefault(_k, [])

    regions, structural_off = _region_headers(data, base_offset)
    if regions is None:
        print(f"{label}  No ECEC signatures found")
        return
    if structural_off is not None:
        print(f"{label}  No ECEC marker - structural ROMHDR @ "
              f"0x{structural_off:X} (CE 2.x)")

    total_mods = 0
    total_files = 0

    for (ecec_off, ptoc_va, romhdr_off_field,
         hdr, romhdr_off, load_offset) in regions:
        nummods = hdr['nummods']
        numfiles = hdr['numfiles']
        machine = resolve_machine(hdr['usCPUType'], machine_override)

        print(f"{label}  XIP @ 0x{ecec_off:X}: {nummods} modules, {numfiles} files "
              f"(load=0x{load_offset:08X})")

        if rom_meta is not None:
            rom_meta['_region_count'] = rom_meta.get('_region_count', 0) + 1

        # Populate rom_meta on the first valid ROMHDR encountered.
        if rom_meta is not None and rom_meta.get('romhdr') is None:
            rom_meta['romhdr'] = {
                'dllfirst':        _hex(hdr['dllfirst']),
                'dlllast':         _hex(hdr['dlllast']),
                'physfirst':       _hex(hdr['physfirst']),
                'physlast':        _hex(hdr['physlast']),
                'ulRAMStart':      _hex(hdr['ulRAMStart']),
                'ulRAMFree_va':    _hex(hdr['ulRAMFree']),
                'ulRAMEnd':        _hex(hdr['ulRAMEnd']),
                'ulCopyEntries':   hdr['ulCopyEntries'],
                'ulCopyOffset':    _hex(hdr['ulCopyOffset']),
                'ulKernelFlags':   _hex(hdr['ulKernelFlags']),
                'ulFSRamPercent':  _hex(hdr['ulFSRamPercent']),
                'ulDrivglobStart': _hex(hdr['ulDrivglobStart']),
                'ulDrivglobLen':   hdr['ulDrivglobLen'],
                'usCPUType':       _hex16(hdr['usCPUType']),
                'usMiscFlags':     _hex16(hdr['usMiscFlags']),
                'pExtensions':     _hex(hdr['pExtensions']),
                'ulTrackingStart': _hex(hdr['ulTrackingStart']),
                'ulTrackingLen':   hdr['ulTrackingLen'],
            }
            rom_meta['rompid'] = parse_rompid_chain(
                data, load_offset, hdr['pExtensions'])
            rom_meta['copy_table'] = parse_copy_table(
                data, load_offset, hdr['ulCopyOffset'], hdr['ulCopyEntries'])
            rom_meta['_romhdr_va_raw'] = ptoc_va
            rom_meta['_cpu_type'] = hdr['usCPUType']
            rom_meta['_romhdr_off'] = romhdr_off_field
            rom_meta['_load_offset'] = load_offset

        if nummods == 0 and numfiles == 0:
            continue

        win_dir = os.path.join(output_dir, "fs", "Windows")
        if not skip_fs:
            os.makedirs(win_dir, exist_ok=True)

        toc_start = romhdr_off + ROMHDR_SIZE
        files_start = toc_start + nummods * TOCENTRY_SIZE

        # Extract modules (PE reconstruction)
        extracted_mods = 0
        for i in range(nummods):
            off = toc_start + i * TOCENTRY_SIZE
            if off + TOCENTRY_SIZE > len(data):
                break
            attrs, ft_lo, ft_hi, fsize, fname_va, e32_va, o32_va, loadoff_va = \
                struct.unpack_from('<8I', data, off)

            fname_foff = fname_va - load_offset
            if 0 <= fname_foff < len(data) - 1:
                fname = read_ascii(data, fname_foff)
            else:
                fname = f"mod_{i}"

            toc_dict = {
                'e32_offset':  e32_va,
                'o32_offset':  o32_va,
                'name_offset': fname_va,
                'load_va':     loadoff_va,
                'file_size':   fsize,
                'attributes':  attrs,
                'filetime_lo': ft_lo,
                'filetime_hi': ft_hi,
            }
            pe_data = reconstruct_pe_xip(
                data, load_offset, e32_va, o32_va,
                machine, heuristic=is_heuristic, toc_dict=toc_dict)
            if pe_data:
                if not skip_fs:
                    outpath = os.path.join(win_dir, safe_filename(fname))
                    with open(outpath, 'wb') as f:
                        f.write(pe_data)
                extracted_mods += 1
                if attr_log is not None:
                    attr_log['\\Windows\\' + fname] = (attrs, (ft_hi << 32) | ft_lo)
                if rom_meta is not None:
                    e32_info = parse_e32_header(data, load_offset, e32_va)
                    objcnt = e32_info['objcnt'] if e32_info else 0
                    secs = parse_section_records(data, load_offset, o32_va, objcnt)
                    rvas = [int(s['rva'], 16) for s in secs]
                    has_shared_rva = len(set(rvas)) != len(rvas)
                    rom_meta['modules'].append({
                        'name':       fname,
                        'shared_rva': has_shared_rva,
                    })
                    # Internal: track each module's section dataptr/psize
                    # ranges so the Sections/ emitter can compute the
                    # complement (bytes not covered by any module's PE).
                    rom_meta.setdefault('_module_ranges', []).extend(
                        (int(s['dataptr'], 16), int(s['psize'], 16))
                        for s in secs
                        if int(s['psize'], 16) > 0
                    )

        # Extract files
        extracted_files = 0
        for i in range(numfiles):
            off = files_start + i * FILEENTRY_SIZE
            if off + FILEENTRY_SIZE > len(data):
                break
            attrs, ft_lo, ft_hi, real_size, comp_size, fname_va, loadoff = \
                struct.unpack_from('<7I', data, off)

            fname_foff = fname_va - load_offset
            if 0 <= fname_foff < len(data) - 1:
                fname = read_ascii(data, fname_foff)
            else:
                fname = f"file_{i}"

            load_foff = loadoff - load_offset
            if 0 <= load_foff < len(data) and comp_size > 0:
                raw = data[load_foff:load_foff + comp_size]
                if comp_size < real_size:
                    dec = ce_rom_decompress(raw, real_size)
                    if dec and len(dec) == real_size:
                        raw = dec
                if not skip_fs:
                    outpath = os.path.join(win_dir, safe_filename(fname))
                    with open(outpath, 'wb') as f:
                        f.write(raw)
                extracted_files += 1
                if attr_log is not None:
                    attr_log['\\Windows\\' + fname] = (attrs, (ft_hi << 32) | ft_lo)
                if rom_meta is not None:
                    compressed_ae = len(raw) != real_size
                    attrs_ae = attrs if compressed_ae else (attrs & ~0x800)
                    rom_meta['files'].append({
                        'name':                            fname,
                        'load_va':                         _hex(loadoff),
                        'real_size':                       real_size,
                        'compressed_size':                 comp_size,
                        'compressed':                      comp_size != real_size,
                        'compressed_after_extraction':     compressed_ae,
                        'compressed_size_after_extraction': len(raw),
                        'attributes':                      _hex(attrs),
                        'attributes_after_extraction':     _hex(attrs_ae),
                        'filetime_lo':                     _hex(ft_lo),
                        'filetime_hi':                     _hex(ft_hi),
                        'name_offset':                     _hex(fname_va),
                    })

        total_mods += extracted_mods
        total_files += extracted_files
        print(f"{label}    -> {extracted_mods} modules, {extracted_files} files")

    return total_mods, total_files
