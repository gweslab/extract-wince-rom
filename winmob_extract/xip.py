"""XIP region extraction: locate ECEC signatures, parse ROMHDR + TOC, emit
PE files for each module and verbatim copies for non-module files.

The ECEC marker (signature 'CECE' little-endian) sits at physfirst+0x40
per romldr.h, followed by ROM_TOC_POINTER_OFFSET (+0x44) and
ROM_TOC_OFFSET_OFFSET (+0x48). Pre-CE5 ROMs only define the signature
slot; +4/+8 may be unused or used as an undocumented convenience.
"""

import base64
import os
import struct

from .util import (u32, u16, read_ascii, safe_filename,
                   ROMHDR_SIZE, TOCENTRY_SIZE, FILEENTRY_SIZE)
from .compress import ce_rom_decompress
from .pe import reconstruct_pe_xip
from .pe.e32 import parse_e32_auto


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
            # VA should be in CE kernel range
            if 0x80000000 <= ptoc_va < 0xC0000000 and romhdr_off < 0x10000000:
                results.append((idx, ptoc_va, romhdr_off))
        pos = idx + 4
    return results


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


def _hex(v):
    return f"0x{v & 0xFFFFFFFF:08X}"


def _hex16(v):
    return f"0x{v & 0xFFFF:04X}"


def extract_xip_regions(data, base_offset, output_dir, label="", attr_log=None,
                        fs_mode='raw', rom_meta=None):
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
    ecec_limit = min(len(data), 0x800000)  # ECEC should be in first 8 MB
    ececs = find_all_ecec(data, limit=ecec_limit)

    if not ececs:
        print(f"{label}  No ECEC signatures found")
        return

    total_mods = 0
    total_files = 0

    for ecec_off, ptoc_va, romhdr_off_field in ececs:
        if romhdr_off_field:
            # ECEC+8 holds the ROMHDR offset from physfirst.
            xip_base = max(ecec_off - 0x40, 0)
            romhdr_off = xip_base + romhdr_off_field
            load_offset = ptoc_va - romhdr_off
            candidates = [(romhdr_off, load_offset)]
        else:
            # ECEC+8 zero: try the explicit base_offset, the kernel-VA
            # mirror (some B000FF images carry physical addresses in the
            # section table while ECEC still carries the virtual VA),
            # and high-bit masks of the value at ECEC+4.
            candidates = [(ptoc_va - base_offset, base_offset)]
            mirror = base_offset | 0x80000000
            if mirror != base_offset:
                candidates.append((ptoc_va - mirror, mirror))
            for mask in (0xFF000000, 0xF0000000):
                cand_load = ptoc_va & mask
                cand_off = ptoc_va - cand_load
                if (cand_off, cand_load) not in candidates:
                    candidates.append((cand_off, cand_load))

        hdr = None
        for romhdr_off, load_offset in candidates:
            if 0 <= romhdr_off and romhdr_off + ROMHDR_SIZE <= len(data):
                h = parse_romhdr(data, romhdr_off)
                if h is not None:
                    hdr = h
                    break
        if hdr is None:
            continue

        nummods = hdr['nummods']
        numfiles = hdr['numfiles']
        machine = hdr['usCPUType'] if hdr['usCPUType'] in (0x01C0, 0x01C2, 0x01C4, 0x014C) else 0x01C0

        print(f"{label}  XIP @ 0x{ecec_off:X}: {nummods} modules, {numfiles} files "
              f"(load=0x{load_offset:08X})")

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
            rom_meta['_romhdr_off'] = romhdr_off_field
            rom_meta['_load_offset'] = load_offset

        if nummods == 0 and numfiles == 0:
            continue

        win_dir = os.path.join(output_dir, "fs", "Windows")
        bad_dir = os.path.join(output_dir, "fs__bad_overlaps")
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

            pe_data, has_shared_rva = reconstruct_pe_xip(
                data, load_offset, e32_va, o32_va,
                machine, heuristic=is_heuristic)
            if pe_data:
                if not skip_fs:
                    if has_shared_rva:
                        os.makedirs(bad_dir, exist_ok=True)
                        outpath = os.path.join(bad_dir, safe_filename(fname))
                    else:
                        outpath = os.path.join(win_dir, safe_filename(fname))
                    with open(outpath, 'wb') as f:
                        f.write(pe_data)
                extracted_mods += 1
                if attr_log is not None:
                    attr_log['\\Windows\\' + fname] = (attrs, (ft_hi << 32) | ft_lo)
                if rom_meta is not None:
                    e32_info = parse_e32_header(data, load_offset, e32_va)
                    objcnt    = e32_info['objcnt']    if e32_info else 0
                    e32_vsize = e32_info['vsize']     if e32_info else fsize
                    e32_vbase = e32_info['vbase']     if e32_info else loadoff_va
                    entry_rva = e32_info['entry_rva'] if e32_info else 0
                    subsystem = e32_info['subsystem'] if e32_info else 0
                    sub_maj   = e32_info['sub_maj']   if e32_info else 0
                    sub_min   = e32_info['sub_min']   if e32_info else 0
                    timestamp = e32_info['timestamp'] if e32_info else 0
                    imgflags  = e32_info['imgflags']  if e32_info else 0
                    # CE marks slot-loaded (non-XIP) modules with the
                    # sentinel ImageBase 0xFFFFF000; XIP modules have a
                    # real fixed VA. Consumers use the flag to decide
                    # whether to pre-place the module's bytes at load_va.
                    rom_meta['modules'].append({
                        'name':            fname,
                        'load_va':         _hex(loadoff_va),
                        'vsize':           _hex(e32_vsize),
                        'entry_rva':       _hex(entry_rva),
                        'subsystem':       subsystem,
                        'subsystem_major': sub_maj,
                        'subsystem_minor': sub_min,
                        'timestamp':       _hex(timestamp),
                        'imgflags':        _hex16(imgflags),
                        'file_size':       fsize,
                        'xip':             e32_vbase != 0xFFFFF000,
                        'compressed':      bool(attrs & 0x800),
                        'shared_rva':      has_shared_rva,
                        'attributes':      _hex(attrs),
                        'filetime_lo':     _hex(ft_lo),
                        'filetime_hi':     _hex(ft_hi),
                        'e32_offset':      _hex(e32_va),
                        'o32_offset':      _hex(o32_va),
                        'name_offset':     _hex(fname_va),
                        'sections':        parse_section_records(
                                               data, load_offset, o32_va, objcnt),
                    })

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
                    rom_meta['files'].append({
                        'name':            fname,
                        'load_va':         _hex(loadoff),
                        'real_size':       real_size,
                        'compressed_size': comp_size,
                        'compressed':      comp_size != real_size,
                        'attributes':      _hex(attrs),
                        'filetime_lo':     _hex(ft_lo),
                        'filetime_hi':     _hex(ft_hi),
                        'name_offset':     _hex(fname_va),
                    })

        total_mods += extracted_mods
        total_files += extracted_files
        print(f"{label}    -> {extracted_mods} modules, {extracted_files} files")

    return total_mods, total_files
