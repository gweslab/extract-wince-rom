"""XIP region extraction: locate ECEC signatures, parse ROMHDR + TOC, emit
PE files for each module and verbatim copies for non-module files."""

import os
import struct

from .util import (u32, read_ascii, safe_filename,
                   ROMHDR_SIZE, TOCENTRY_SIZE, FILEENTRY_SIZE)
from .compress import ce_rom_decompress
from .pe import reconstruct_pe_xip


def find_all_ecec(data, limit=None):
    """Find all ECEC signatures that look like valid XIP region markers."""
    results = []
    end = limit if limit else len(data)
    pos = 0
    while pos < end - 12:
        idx = data.find(b'ECEC', pos)
        if idx == -1 or idx >= end:
            break
        if idx + 12 <= len(data):
            romhdr_va = u32(data, idx + 4)
            romhdr_phys = u32(data, idx + 8)
            # VA should be in CE kernel range
            if 0x80000000 <= romhdr_va < 0xC0000000 and romhdr_phys < 0x10000000:
                results.append((idx, romhdr_va, romhdr_phys))
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


def extract_xip_regions(data, base_offset, output_dir, label="", attr_log=None):
    """Find and extract all XIP regions from a flat image.

    data:        flat image bytes
    base_offset: the VA or load base that converts VAs to offsets in data
                 (file_offset = VA - base_offset)
    output_dir:  root output directory
    label:       prefix for log messages
    attr_log:    optional dict; if provided, records the original CE file
                 attribute bits and FILETIME for every emitted module/file as
                 attr_log['\\Windows\\<name>'] = (attrs_int, filetime_u64).
    """
    ecec_limit = min(len(data), 0x800000)  # ECEC should be in first 8 MB
    ececs = find_all_ecec(data, limit=ecec_limit)

    if not ececs:
        print(f"{label}  No ECEC signatures found")
        return

    total_mods = 0
    total_files = 0

    for ecec_off, romhdr_va, romhdr_phys in ececs:
        if romhdr_phys:
            # Standard layout: romhdr_phys is the file offset within the XIP region
            xip_base = max(ecec_off - 0x40, 0)
            romhdr_off = xip_base + romhdr_phys
            load_offset = romhdr_va - romhdr_off
            candidates = [(romhdr_off, load_offset)]
        else:
            # romhdr_phys=0: ROMHDR is reachable only via VA. Try the explicit
            # base_offset first (WM2003 B000FF), then derive a load base from
            # romhdr_va's high bits (NB0 PocketPC 2000, where the file is just
            # the raw ROM mapped at e.g. 0x80000000 with no section header).
            candidates = [(romhdr_va - base_offset, base_offset)]
            for mask in (0xFF000000, 0xF0000000):
                cand_load = romhdr_va & mask
                cand_off = romhdr_va - cand_load
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

        if nummods == 0 and numfiles == 0:
            continue

        out_dir = os.path.join(output_dir, "Windows")
        os.makedirs(out_dir, exist_ok=True)

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

            pe_data = reconstruct_pe_xip(data, load_offset, e32_va, o32_va, machine)
            if pe_data:
                outpath = os.path.join(out_dir, safe_filename(fname))
                with open(outpath, 'wb') as f:
                    f.write(pe_data)
                extracted_mods += 1
                if attr_log is not None:
                    attr_log['\\Windows\\' + fname] = (attrs, (ft_hi << 32) | ft_lo)

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
                outpath = os.path.join(out_dir, safe_filename(fname))
                with open(outpath, 'wb') as f:
                    f.write(raw)
                extracted_files += 1
                if attr_log is not None:
                    attr_log['\\Windows\\' + fname] = (attrs, (ft_hi << 32) | ft_lo)

        total_mods += extracted_mods
        total_files += extracted_files
        print(f"{label}    -> {extracted_mods} modules, {extracted_files} files")

    return total_mods, total_files
