#!/usr/bin/env python3

import struct
import os
import sys
import shutil

from wince_decompr.wincedecompr import CEDecompressROM as _lzx_decompress_rom

# ── Struct sizes ─────────────────────────────────────────────────────────────

ROMHDR_SIZE = 84        # sizeof(ROMHDR) from loadbin_nb0.h
TOCENTRY_SIZE = 32      # sizeof(TOCentry)
FILEENTRY_SIZE = 28     # sizeof(FILESentry)
SECTION_HEADER_SIZE = 12  # sizeof(CESectionHeader) from loadbin_nb0.cpp

# ── IMGFS constants ──────────────────────────────────────────────────────────

IMGFS_UUID = bytes([
    0xF8, 0xAC, 0x2C, 0x9D, 0xE3, 0xD4, 0x2B, 0x4D,
    0xBD, 0x30, 0x91, 0x6E, 0xD8, 0x4F, 0x31, 0xDC,
])
IMGFS_DIR_MAGIC = 0x2F5314CE
IMGFS_DIRENT_SIZE = 0x34  # 52 bytes

MAGIC_MODULE  = 0xFFFFFEFE
MAGIC_FILE    = 0xFFFFF6FE
MAGIC_NAME    = 0xFFFFFEFB
MAGIC_SECTION = 0xFFFFF6FD

# ── Helpers ──────────────────────────────────────────────────────────────────

def u16(data, off):
    return struct.unpack_from('<H', data, off)[0]


def u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def read_ascii(data, off, maxlen=256):
    end = data.find(b'\x00', off, off + maxlen)
    if end == -1:
        end = off + maxlen
    return data[off:end].decode('ascii', errors='replace')


def safe_filename(name):
    """Sanitise a filename for the host filesystem."""
    for ch in '\\/:*?"<>|':
        name = name.replace(ch, '_')
    while name.startswith('.'):
        name = '_' + name[1:]
    return name or 'unnamed'


# ── LZ77 decompression ───────────────────────────────────────────────────────
#
# Windows CE uses two LZ77 variants, both MSB-first:
#
#  1) ROM section compression (CeCompress / DecompressBinaryBlock):
#     Extended match lengths use a full byte, no nibble sharing.
#     Used for compressed XIP module sections (flag 0x2000 in o32_rom).
#
#  2) IMGFS XPRESS compression (XPR):
#     Extended match lengths use nibble-sharing — consecutive extended
#     matches alternate low/high nibbles of a shared byte.
#     Used for file data chunks inside IMGFS.


def _lz77_core(src, out_size, nibble_sharing):
    """
    Core LZ77 decompressor for both CE variants.

    Flag bits are processed MSB-first (bit 31 → 0).
    match descriptor:  offset = (val >> 3) + 1,  base_len = val & 7
    If base_len == 7 → extended length read.
    """
    slen = len(src)
    dst = bytearray(out_size)
    si = 0
    di = 0
    nibble_idx = 0  # only used when nibble_sharing is True

    while si < slen and di < out_size:
        if si + 4 > slen:
            break
        flags = struct.unpack_from('<I', src, si)[0]
        si += 4

        for bit in range(31, -1, -1):
            if si >= slen or di >= out_size:
                break

            if not (flags & (1 << bit)):
                # Literal byte
                dst[di] = src[si]
                si += 1
                di += 1
            else:
                # Match reference
                if si + 2 > slen:
                    return bytes(dst[:di])
                val = struct.unpack_from('<H', src, si)[0]
                si += 2
                match_off = (val >> 3) + 1
                match_len = val & 7

                if match_len == 7:
                    if nibble_sharing:
                        # Nibble-sharing: alternate low/high nibbles
                        if nibble_idx == 0:
                            if si >= slen:
                                return bytes(dst[:di])
                            nibble_idx = si
                            match_len = src[si] & 0x0F
                            si += 1
                        else:
                            match_len = src[nibble_idx] >> 4
                            nibble_idx = 0
                    else:
                        # Full byte extension
                        if si >= slen:
                            return bytes(dst[:di])
                        match_len = src[si]
                        si += 1

                    if match_len == 15:
                        if si >= slen:
                            return bytes(dst[:di])
                        match_len = src[si]
                        si += 1
                        if match_len == 255:
                            if si + 2 > slen:
                                return bytes(dst[:di])
                            match_len = struct.unpack_from('<H', src, si)[0]
                            si += 2
                            if match_len == 0:
                                if si + 4 > slen:
                                    return bytes(dst[:di])
                                match_len = struct.unpack_from('<I', src, si)[0]
                                si += 4
                            if match_len < 22:
                                return bytes(dst[:di])
                            match_len -= 22
                        match_len += 15
                    match_len += 7

                match_len += 3
                copy_from = di - match_off

                if copy_from >= 0 and copy_from + match_len <= di:
                    end = min(di + match_len, out_size)
                    n = end - di
                    dst[di:end] = dst[copy_from:copy_from + n]
                    di = end
                else:
                    for _ in range(match_len):
                        if di >= out_size:
                            break
                        p = copy_from
                        copy_from += 1
                        dst[di] = dst[p] if 0 <= p < di else 0
                        di += 1

    return bytes(dst[:di]) if di < out_size else bytes(dst)


def ce_rom_decompress(src, out_size):
    """Decompress a CE ROM compressed section using LZX (BinDecompressROM)."""
    dcbuf = bytearray(out_size + 4096)
    try:
        rlen = _lzx_decompress_rom(bytes(src), len(src), dcbuf, out_size, 0, 1, 4096)
    except Exception:
        rlen = -1
    if rlen > 0:
        result = bytes(dcbuf[:rlen])
        if len(result) < out_size:
            result += b'\x00' * (out_size - len(result))
        return result
    return b'\x00' * out_size  # fallback: zero-fill on failure


def xpress_decompress(src, out_size):
    """Decompress IMGFS XPRESS data (nibble-sharing extension)."""
    return _lz77_core(src, out_size, nibble_sharing=True)


def try_decompress(chunk, full_size):
    """Try IMGFS decompression; return decompressed data or None."""
    if len(chunk) == full_size:
        return chunk  # stored uncompressed
    if len(chunk) == 0:
        return None
    result = xpress_decompress(chunk, full_size)
    if len(result) == full_size:
        return result
    return None


# ── PE reconstruction ────────────────────────────────────────────────────────

# CE data-directory indices → PE data-directory indices
_CE_TO_PE_DD = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 12, 8: 14}

# e32rom offsets
_E32_DD_XIP  = 0x20   # data dirs offset for XIP (CE 4.x, no timestamp)
_E32_DD_IMGFS = 0x24  # data dirs offset for IMGFS/WM6 XIP (has timestamp @ 0x20)
_O32_SIZE = 24         # sizeof(o32_rom)


def _section_name(flags, rva, ce_dds):
    """Infer PE section name from o32 flags and data-directory hits."""
    for idx, (dd_rva, dd_sz) in enumerate(ce_dds):
        if dd_rva == rva and dd_sz > 0:
            if idx == 2:
                return b'.rsrc\x00\x00\x00'
            if idx == 5:
                return b'.reloc\x00\x00'
    if flags & 0x20:
        return b'.text\x00\x00\x00'
    if flags & 0x80:
        return b'.bss\x00\x00\x00\x00'
    if flags & 0x40:
        return b'.data\x00\x00\x00' if flags & 0x80000000 else b'.rdata\x00\x00'
    return b'.sec\x00\x00\x00\x00'


def _align(v, a):
    return (v + a - 1) & ~(a - 1)


def build_pe(objcnt, imgflags, entry_rva, vbase, subsys_maj, subsys_min,
             stackmax, vsize, timestamp, ce_dds, sections, machine=0x01C0,
             subsystem=9, sect14_rva=0, sect14_size=0):
    """
    Assemble a PE32 file from parsed e32rom fields and raw section data.

    Every field comes from the e32rom header — nothing is invented.
    Fields not present in e32rom are set to 0.

    sections: list of dicts {name, vsize, rva, raw_size, flags, data}
    ce_dds:   list of (rva, size) for 9 CE data directories
    """
    FA = 0x200
    SA = 0x1000
    PE_DDS = 16

    dos_sz = 64
    pe_sig_sz = 4
    coff_sz = 20
    opt_sz = 224           # PE32: 96 fixed + 16*8 data-dirs
    sechdr_sz = len(sections) * 40

    hdr_raw = dos_sz + pe_sig_sz + coff_sz + opt_sz + sechdr_sz
    hdr_aligned = _align(hdr_raw, FA)

    foff = hdr_aligned
    for s in sections:
        s['foff'] = foff
        s['raw_a'] = _align(s['raw_size'], FA) if s['raw_size'] > 0 else 0
        foff += s['raw_a']

    # SizeOfImage: last section RVA + section-aligned vsize
    if sections:
        last = sections[-1]
        size_of_image = _align(last['rva'] + last['vsize'], SA)
    else:
        size_of_image = _align(hdr_aligned, SA)

    pe = bytearray(foff)

    # DOS header
    pe[0:2] = b'MZ'
    struct.pack_into('<I', pe, 0x3C, dos_sz)

    # PE signature
    p = dos_sz
    pe[p:p + 4] = b'PE\x00\x00'
    p += 4

    # COFF header
    # Characteristics: use e32_imageflags directly, ensure EXECUTABLE_IMAGE
    chars = imgflags | 0x0002
    struct.pack_into('<HHIIIHH', pe, p,
                     machine, len(sections), timestamp, 0, 0, opt_sz, chars)
    p += coff_sz

    # Optional header (PE32)
    # All fields from e32rom or computed — no hardcoded magic values.
    o = p
    code_sz   = sum(s['raw_a'] for s in sections if s['flags'] & 0x20)
    idata_sz  = sum(s['raw_a'] for s in sections if s['flags'] & 0x40)
    udata_sz  = sum(s['vsize'] for s in sections if s['flags'] & 0x80)
    base_code = sections[0]['rva'] if sections else SA
    base_data = next((s['rva'] for s in sections if s['flags'] & 0x40), 0)

    struct.pack_into('<H', pe, o, 0x10B)              # +0  Magic = PE32
    # +2,+3 LinkerMajor/Minor: 0 (not in e32rom)
    struct.pack_into('<III', pe, o + 4, code_sz, idata_sz, udata_sz)
    struct.pack_into('<I',  pe, o + 16, entry_rva)     # +16 AddressOfEntryPoint
    struct.pack_into('<I',  pe, o + 20, base_code)     # +20 BaseOfCode
    struct.pack_into('<I',  pe, o + 24, base_data)     # +24 BaseOfData
    struct.pack_into('<I',  pe, o + 28, vbase)         # +28 ImageBase
    struct.pack_into('<II', pe, o + 32, SA, FA)        # +32 SectionAlignment, FileAlignment
    struct.pack_into('<HH', pe, o + 40, subsys_maj, subsys_min)  # +40 OS Major/Minor (= subsys version from e32rom)
    # +44,+46 ImageMajor/Minor: 0 (not in e32rom)
    struct.pack_into('<HH', pe, o + 48, subsys_maj, subsys_min)  # +48 SubsystemMajor/Minor
    # +52 Win32VersionValue: 0
    struct.pack_into('<II', pe, o + 56, size_of_image, hdr_aligned)  # +56 SizeOfImage, +60 SizeOfHeaders
    # +64 CheckSum: 0
    struct.pack_into('<H',  pe, o + 68, subsystem)     # +68 Subsystem (from e32_subsys)
    # +70 DllCharacteristics: 0 (not in e32rom)
    struct.pack_into('<I',  pe, o + 72, stackmax)      # +72 SizeOfStackReserve (from e32_stackmax)
    # +76 StackCommit, +80 HeapReserve, +84 HeapCommit: 0 (not in e32rom)
    # +88 LoaderFlags: 0
    struct.pack_into('<I',  pe, o + 92, PE_DDS)        # +92 NumberOfRvaAndSizes

    # Data directories: map CE e32_unit[0..8] to PE DataDirectory[0..15]
    dd_base = o + 96
    for ce_i, (dd_rva, dd_sz) in enumerate(ce_dds):
        pe_i = _CE_TO_PE_DD.get(ce_i)
        if pe_i is not None and dd_rva:
            struct.pack_into('<II', pe, dd_base + pe_i * 8, dd_rva, dd_sz)
    # e32_sect14rva/size → DataDirectory[14] (CLR/RS4)
    if sect14_rva:
        struct.pack_into('<II', pe, dd_base + 14 * 8, sect14_rva, sect14_size)

    p += opt_sz

    # Section headers
    for i, s in enumerate(sections):
        h = p + i * 40
        pe[h:h + 8] = s['name'][:8].ljust(8, b'\x00')
        struct.pack_into('<IIIIII', pe, h + 8,
                         s['vsize'], s['rva'], s['raw_a'], s['foff'], 0, 0)
        struct.pack_into('<HH', pe, h + 32, 0, 0)
        struct.pack_into('<I', pe, h + 36, s['flags'] & ~0x2002)

    # Section data
    for s in sections:
        if s['data']:
            pe[s['foff']:s['foff'] + len(s['data'])] = s['data']

    return bytes(pe)


def _parse_e32_base(data, off, dd_offset):
    """Parse common e32rom fields.  Returns dict or None."""
    if off < 0 or off + dd_offset + 72 > len(data):
        return None
    objcnt    = u16(data, off)
    imgflags  = u16(data, off + 2)
    entry_rva = u32(data, off + 4)
    vbase     = u32(data, off + 8)
    sub_maj   = u16(data, off + 0x0C)
    sub_min   = u16(data, off + 0x0E)
    stackmax  = u32(data, off + 0x10)
    vsize     = u32(data, off + 0x14)
    ts = u32(data, off + 0x20) if dd_offset == _E32_DD_IMGFS else 0

    ce_dds = []
    for i in range(9):
        d = off + dd_offset + i * 8
        ce_dds.append((u32(data, d), u32(data, d + 4)))

    # e32_subsys is at offset 0x6C (after 9 data dirs ending at dd_offset + 72)
    subsys_off = dd_offset + 72
    subsys = u16(data, off + subsys_off) if off + subsys_off + 2 <= len(data) else 9

    sect14_rva = u32(data, off + 0x18)
    sect14_size = u32(data, off + 0x1C)

    return dict(objcnt=objcnt, imgflags=imgflags, entry_rva=entry_rva,
                vbase=vbase, sub_maj=sub_maj, sub_min=sub_min,
                stackmax=stackmax, vsize=vsize, timestamp=ts, ce_dds=ce_dds,
                subsystem=subsys, sect14_rva=sect14_rva, sect14_size=sect14_size)


def _fix_iat_from_ilt(pe_data):
    """Overwrite IAT entries with ILT values so the PE has proper import hints
    instead of ROM-baked resolved addresses."""
    if not pe_data or len(pe_data) < 0x80:
        return pe_data
    pe = bytearray(pe_data)
    pe_off = struct.unpack_from('<I', pe, 0x3C)[0]
    if pe_off + 24 > len(pe) or pe[pe_off:pe_off + 4] != b'PE\x00\x00':
        return pe_data
    num_sec = struct.unpack_from('<H', pe, pe_off + 6)[0]
    opt_off = pe_off + 24
    opt_sz = struct.unpack_from('<H', pe, pe_off + 20)[0]
    # PE32 DataDirectory starts at opt_off + 96; DD[1] = Import Directory
    dd_base = opt_off + 96
    if dd_base + 16 > len(pe):
        return pe_data
    imp_rva, imp_sz = struct.unpack_from('<II', pe, dd_base + 8)
    if imp_rva == 0 or imp_sz == 0:
        return pe_data

    # Build RVA → file offset map from section table
    sec_off = opt_off + opt_sz
    sec_map = []
    for i in range(num_sec):
        h = sec_off + i * 40
        s_vsize, s_rva, s_rawsz, s_rawptr = struct.unpack_from('<IIII', pe, h + 8)
        sec_map.append((s_rva, max(s_vsize, s_rawsz), s_rawptr))

    def rva_to_foff(rva):
        for s_rva, s_sz, s_foff in sec_map:
            if s_rva <= rva < s_rva + s_sz:
                return s_foff + (rva - s_rva)
        return -1

    # Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each, null-terminated)
    imp_foff = rva_to_foff(imp_rva)
    if imp_foff < 0:
        return pe_data
    pos = imp_foff
    while pos + 20 <= len(pe):
        ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from('<IIIII', pe, pos)
        if ilt_rva == 0 and iat_rva == 0:
            break
        pos += 20
        if ilt_rva == 0 or iat_rva == 0:
            continue
        ilt_foff = rva_to_foff(ilt_rva)
        iat_foff = rva_to_foff(iat_rva)
        if ilt_foff < 0 or iat_foff < 0:
            continue
        # Copy ILT entries to IAT entries (4 bytes each, null-terminated)
        i = 0
        while True:
            ilt_pos = ilt_foff + i * 4
            iat_pos = iat_foff + i * 4
            if ilt_pos + 4 > len(pe) or iat_pos + 4 > len(pe):
                break
            val = struct.unpack_from('<I', pe, ilt_pos)[0]
            if val == 0:
                # Also zero out the IAT terminator
                struct.pack_into('<I', pe, iat_pos, 0)
                break
            struct.pack_into('<I', pe, iat_pos, val)
            i += 1

    return bytes(pe)


def reconstruct_pe_xip(flat, base_off, e32_va, o32_va, machine=0x01C0,
                        dd_offset=_E32_DD_IMGFS):
    """Build PE from XIP module (separate e32/o32 pointers in flat image)."""
    e32 = e32_va - base_off
    o32 = o32_va - base_off
    info = _parse_e32_base(flat, e32, dd_offset)
    if info is None:
        return None
    n = info['objcnt']
    if o32 < 0 or o32 + n * _O32_SIZE > len(flat):
        return None

    sections = []
    realaddr_map = []  # (section_rva, real_addr, vsize) for split-address sections
    for s in range(n):
        so = o32 + s * _O32_SIZE
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
            name=_section_name(sf, sr, info['ce_dds']),
            vsize=sv, rva=sr, raw_size=len(data) if data else sp,
            flags=sf, data=data))
        # Track sections where o32_realaddr differs from the PE address
        if sa != 0 and sa != info['vbase'] + sr:
            realaddr_map.append((sr, sa, sv))

    # For each data directory, check if the RVA is covered by a section.
    # If not, try to fetch the data from the flat image and add as extra section.
    # If the data isn't available, clear the DD entry so the PE isn't broken.
    vbase = info['vbase']
    ce_dds = list(info['ce_dds'])  # make mutable copy
    SA = 0x1000

    dd_names_short = ['.edata','.idata','.rsrc','.pdata','.certs','.reloc','.debug','.imd','.msp']
    for dd_i in range(len(ce_dds)):
        dd_rva, dd_sz = ce_dds[dd_i]
        if dd_rva == 0 or dd_sz == 0:
            continue
        # Check if any existing section covers this RVA
        covered = False
        for sec in sections:
            if sec['rva'] <= dd_rva < sec['rva'] + max(sec['vsize'], sec['raw_size']):
                covered = True
                break
        if covered:
            continue
        # DD points outside existing sections — try to read from flat image
        dd_va = vbase + dd_rva
        dd_flat = dd_va - base_off
        if 0 <= dd_flat and dd_flat + dd_sz <= len(flat):
            # Data available — add as extra section
            dd_data = bytes(flat[dd_flat:dd_flat + dd_sz])
            sec_rva = _align(dd_rva, SA)
            if dd_rva % SA != 0:
                # Pad to align RVA
                pad = dd_rva - sec_rva
                dd_data = b'\x00' * pad + dd_data
                sec_rva = dd_rva - pad
            sec_name = dd_names_short[dd_i] if dd_i < len(dd_names_short) else f'.dd{dd_i}'
            sections.append(dict(
                name=sec_name.encode('ascii').ljust(8, b'\x00')[:8],
                vsize=_align(len(dd_data), SA),
                rva=sec_rva,
                raw_size=len(dd_data),
                flags=0x40000040,  # INITIALIZED_DATA | MEM_READ
                data=dd_data))
        else:
            # Data not available — clear the DD so PE tools don't crash
            ce_dds[dd_i] = (0, 0)

    # Step 1: Patch absolute realaddr references (data sections at different RAM addr)
    if realaddr_map:
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

    # Step 2: Unified scan for ALL absolute references within PE image range
    # Covers: patched realaddr refs, vtable entries, function pointers, literal pools
    size_of_image = _align(max(s['rva'] + s['vsize'] for s in sections), SA)

    # Build exclude ranges for low-base modules where RVAs collide with image VAs.
    # High-base modules (vbase >= size_of_image) can't have RVA/VA collisions.
    exclude = []
    if vbase < size_of_image:
        def _sec_data_at(rva):
            for s in sections:
                if s['data'] and s['rva'] <= rva < s['rva'] + len(s['data']):
                    return s['data'], rva - s['rva']
            return None, 0

        # Export directory (DD[0]): exclude 40-byte header + name tables, NOT function table
        exp_rva, exp_sz = ce_dds[0] if len(ce_dds) > 0 else (0, 0)
        if exp_rva and exp_sz:
            exclude.append((exp_rva, exp_rva + 40))  # IMAGE_EXPORT_DIRECTORY header
            d, off = _sec_data_at(exp_rva)
            if d and off + 40 <= len(d):
                num_funcs = struct.unpack_from('<I', d, off + 20)[0]
                names_rva = struct.unpack_from('<I', d, off + 32)[0]
                ords_rva = struct.unpack_from('<I', d, off + 36)[0]
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

        # IAT (CE DD[7] → PE DD[12]): ordinal hints after IAT fix
        if len(ce_dds) > 7:
            iat_rva, iat_sz = ce_dds[7]
            if iat_rva and iat_sz:
                exclude.append((iat_rva, iat_rva + iat_sz))

    def _in_exclude(rva):
        for start, end in exclude:
            if start <= rva < end:
                return True
        return False

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

    def _get_code_ranges(pdata_rva, pdata_sz, text_rva, text_vsize):
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

    # .pdata (CE DD[3])
    pdata_rva, pdata_sz = ce_dds[3] if len(ce_dds) > 3 else (0, 0)

    reloc_rvas = []
    for sec in sections:
        if not sec['data'] or sec['name'].startswith(b'.reloc'):
            continue
        if sec['flags'] & 0x20:
            # Code section: LDR pools (within functions) + pdata gaps (between functions)
            ldr_offsets = _find_literal_pool_offsets(sec['data'])
            pdata_offsets = set()
            if pdata_rva and pdata_sz:
                code_ranges = _get_code_ranges(pdata_rva, pdata_sz, sec['rva'], sec['vsize'])
                if code_ranges:
                    for off in range(0, len(sec['data']) - 3, 4):
                        if not _is_in_code(off, code_ranges):
                            val = struct.unpack_from('<I', sec['data'], off)[0]
                            if vbase <= val < vbase + size_of_image:
                                pdata_offsets.add(off)
            for off in sorted(ldr_offsets | pdata_offsets):
                val = struct.unpack_from('<I', sec['data'], off)[0]
                if vbase <= val < vbase + size_of_image:
                    abs_rva = sec['rva'] + off
                    if not _in_exclude(abs_rva):
                        reloc_rvas.append(abs_rva)
        else:
            # Data sections: scan all 4-byte aligned values
            for off in range(0, len(sec['data']) - 3, 4):
                val = struct.unpack_from('<I', sec['data'], off)[0]
                if vbase <= val < vbase + size_of_image:
                    abs_rva = sec['rva'] + off
                    if not _in_exclude(abs_rva):
                        reloc_rvas.append(abs_rva)

    # Step 3: Build PE .reloc section from all discovered relocations
    if reloc_rvas:
        reloc_rvas.sort()
        reloc_blocks = bytearray()
        i = 0
        while i < len(reloc_rvas):
            page = reloc_rvas[i] & ~0xFFF
            entries = []
            while i < len(reloc_rvas) and (reloc_rvas[i] & ~0xFFF) == page:
                entries.append((3 << 12) | (reloc_rvas[i] & 0xFFF))
                i += 1
            if len(entries) & 1:
                entries.append(0)  # padding to align block
            block_sz = 8 + len(entries) * 2
            reloc_blocks += struct.pack('<II', page, block_sz)
            for e in entries:
                reloc_blocks += struct.pack('<H', e)
        reloc_data = bytes(reloc_blocks)
        max_rva = max(s['rva'] + max(s['vsize'], s['raw_size']) for s in sections)
        reloc_rva = _align(max_rva, SA)
        sections.append(dict(
            name=b'.reloc\x00\x00',
            vsize=len(reloc_data),
            rva=reloc_rva,
            raw_size=len(reloc_data),
            flags=0x42000040,  # INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ
            data=reloc_data))
        ce_dds[5] = (reloc_rva, len(reloc_data))

    # Sort sections by RVA
    sections.sort(key=lambda s: s['rva'])

    pe_data = build_pe(n, info['imgflags'], info['entry_rva'], info['vbase'],
                    info['sub_maj'], info['sub_min'], info['stackmax'],
                    info['vsize'], info['timestamp'], ce_dds,
                    sections, machine, info.get('subsystem', 9),
                    info.get('sect14_rva', 0), info.get('sect14_size', 0))
    return _fix_iat_from_ilt(pe_data) if pe_data else None


def reconstruct_pe_imgfs(header_data, section_data_map):
    """Build PE from IMGFS module (combined e32rom+o32_rom header blob)."""
    if not header_data or len(header_data) < 0x70:
        return None
    info = _parse_e32_base(header_data, 0, _E32_DD_IMGFS)
    if info is None:
        return None
    n = info['objcnt']
    if len(header_data) < 0x70 + n * _O32_SIZE:
        return None

    sections = []
    for s in range(n):
        so = 0x70 + s * _O32_SIZE
        sv, sr, sp, sd, sa, sf = struct.unpack_from('<6I', header_data, so)
        key = f'S{s:03d}'
        data = section_data_map.get(key, b'')
        sections.append(dict(
            name=_section_name(sf, sr, info['ce_dds']),
            vsize=sv, rva=sr, raw_size=len(data) if data else sp,
            flags=sf, data=data))

    pe_data = build_pe(n, info['imgflags'], info['entry_rva'], info['vbase'],
                    info['sub_maj'], info['sub_min'], info['stackmax'],
                    info['vsize'], info['timestamp'], info['ce_dds'],
                    sections, subsystem=info.get('subsystem', 9),
                    sect14_rva=info.get('sect14_rva', 0),
                    sect14_size=info.get('sect14_size', 0))
    return _fix_iat_from_ilt(pe_data) if pe_data else None


# ── B000FF container parsing ─────────────────────────────────────────────────

def parse_b000ff(data):
    """
    Parse a B000FF container image into a flat VA-indexed byte array.

    Format (from Device Emulator loadbin_nb0.cpp):
      - 7 bytes  : "B000FF\\n"
      - 4 bytes  : image start address
      - 4 bytes  : image length
      - sections : each = 12-byte CESectionHeader + fSectionSize bytes of data
      - terminator: section with fSectionBaseAddress == 0

    Returns (flat, min_va) or (None, None) on failure.
    """
    if data[:7] != b'B000FF\n':
        return None, None

    start_addr = u32(data, 7)
    off = 15  # skip sig (7) + addr (4) + len (4)

    records = []
    while off + SECTION_HEADER_SIZE <= len(data):
        base = u32(data, off)
        size = u32(data, off + 4)
        # checksum at off+8, ignored for extraction
        if base == 0:
            break
        data_off = off + SECTION_HEADER_SIZE
        if data_off + size > len(data) or size > 0x10000000:
            break
        records.append((base, size, data_off))
        off = data_off + size

    if not records:
        return None, None

    min_va = min(r[0] for r in records)
    max_end = max(r[0] + r[1] for r in records)
    flat = bytearray(max_end - min_va)
    for addr, length, file_off in records:
        flat[addr - min_va:addr - min_va + length] = data[file_off:file_off + length]

    print(f"  B000FF: {len(records)} sections, VA range "
          f"0x{min_va:08X}..0x{max_end:08X} ({len(flat) / 1024:.0f} KB)")
    return bytes(flat), min_va


# ── XIP extraction ───────────────────────────────────────────────────────────

def _find_all_ecec(data, limit=None):
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


def _parse_romhdr(data, off):
    """Parse ROMHDR at the given offset.  Returns dict or None."""
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


def extract_xip_regions(data, base_offset, output_dir, label=""):
    """
    Find and extract all XIP regions from a flat image.

    data:        flat image bytes
    base_offset: the VA or load base that converts VAs to offsets in data
                 (file_offset = VA - base_offset)
    output_dir:  root output directory
    label:       prefix for log messages
    """
    ecec_limit = min(len(data), 0x800000)  # ECEC should be in first 8 MB
    ececs = _find_all_ecec(data, limit=ecec_limit)

    if not ececs:
        print(f"{label}  No ECEC signatures found")
        return

    total_mods = 0
    total_files = 0

    for ecec_off, romhdr_va, romhdr_phys in ececs:
        # XIP base is 0x40 before the ECEC marker
        xip_base = max(ecec_off - 0x40, 0)
        romhdr_off = xip_base + romhdr_phys
        load_offset = romhdr_va - romhdr_off

        hdr = _parse_romhdr(data, romhdr_off)
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

        # ── Extract modules (PE reconstruction) ──
        extracted_mods = 0
        for i in range(nummods):
            off = toc_start + i * TOCENTRY_SIZE
            if off + TOCENTRY_SIZE > len(data):
                break
            attrs, ft_lo, ft_hi, fsize, fname_va, e32_va, o32_va, loadoff_va = \
                struct.unpack_from('<8I', data, off)

            # Read filename
            fname_foff = fname_va - load_offset
            if 0 <= fname_foff < len(data) - 1:
                fname = read_ascii(data, fname_foff)
            else:
                fname = f"mod_{i}"

            pe_data = reconstruct_pe_xip(data, load_offset, e32_va, o32_va,
                                          machine, dd_offset=_E32_DD_IMGFS)
            if pe_data is None:
                # Retry with XIP (no-timestamp) layout
                pe_data = reconstruct_pe_xip(data, load_offset, e32_va, o32_va,
                                              machine, dd_offset=_E32_DD_XIP)
            if pe_data:
                outpath = os.path.join(out_dir, safe_filename(fname))
                with open(outpath, 'wb') as f:
                    f.write(pe_data)
                extracted_mods += 1

        # ── Extract files ──
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

        total_mods += extracted_mods
        total_files += extracted_files
        print(f"{label}    -> {extracted_mods} modules, {extracted_files} files")

    return total_mods, total_files


# ── FTL (Flash Translation Layer) ───────────────────────────────────────────

def build_ftl_mapping(data, imgfs_base):
    """
    Build logical-sector → physical-page mapping from NAND erase-block
    mapping tables.

    Each 64 KB erase block has 15 data pages (4 KB) + 1 mapping page.
    The mapping page contains 15 × 8-byte entries:
        uint32 logical_sector | uint32 flags

    Returns (base_sector, mapping_dict) or (None, {}).
    """
    erase_sz = 0x10000    # 64 KB
    page_sz  = 0x1000     # 4 KB
    dpb      = 15         # data pages per block

    imgfs_size = len(data) - imgfs_base
    num_blocks = imgfs_size // erase_sz

    # Heuristic: sample first blocks to decide if FTL is present
    valid = total = 0
    for blk in range(min(8, num_blocks)):
        map_off = imgfs_base + blk * erase_sz + dpb * page_sz
        for e in range(dpb):
            eo = map_off + e * 8
            if eo + 8 > len(data):
                break
            ls = u32(data, eo)
            fl = u32(data, eo + 4)
            total += 1
            if ls != 0xFFFFFFFF and (fl & 0xFFF00000) == 0xFFF00000:
                valid += 1

    if total == 0 or valid < total * 0.4:
        return None, {}

    # Build full mapping (with flag validation)
    mapping = {}
    for blk in range(num_blocks):
        map_off = imgfs_base + blk * erase_sz + dpb * page_sz
        for e in range(dpb):
            eo = map_off + e * 8
            if eo + 8 > len(data):
                break
            ls = u32(data, eo)
            fl = u32(data, eo + 4)
            if ls == 0xFFFFFFFF:
                continue
            if (fl & 0xFFF00000) != 0xFFF00000:
                continue  # skip entries with invalid flags
            phys_page = blk * (dpb + 1) + e
            mapping[ls] = phys_page

    # Find base sector (the one mapping to physical page 0 = superblock)
    base_sector = None
    for s, p in mapping.items():
        if p == 0:
            base_sector = s
            break

    return base_sector, mapping


def make_ftl_translate(imgfs_base, base_sector, mapping):
    """Return a function: IMGFS logical address → absolute file offset."""
    def translate(la):
        if la == 0:
            return None
        page = la // 0x1000
        sector = page + base_sector
        phys = mapping.get(sector)
        if phys is None:
            return None
        return imgfs_base + phys * 0x1000 + (la & 0xFFF)
    return translate


def make_direct_translate(imgfs_base, data_len):
    """Return a translate function for NOR flash (no FTL)."""
    def translate(la):
        if la == 0:
            return None
        a = imgfs_base + la
        return a if a < data_len else None
    return translate


# ── IMGFS extraction ─────────────────────────────────────────────────────────

def _resolve_name(data, translate, nameinfo, name_map):
    """Resolve a 12-byte nameinfo structure to a filename string."""
    length = u16(nameinfo, 0)
    flags  = u16(nameinfo, 2)

    if length == 0:
        return ""

    if length <= 4:
        nb = nameinfo[4:4 + length * 2]
        return nb.decode('utf-16-le', errors='replace').rstrip('\x00')

    ptr = u32(nameinfo, 8)

    if flags & 0x02:
        # Pointer to a NAME directory entry
        off = translate(ptr)
        if off is not None and off + 52 <= len(data):
            if u32(data, off) == MAGIC_NAME:
                nb = data[off + 4:off + 52]
                return nb.decode('utf-16-le', errors='replace').rstrip('\x00')
        # Fallback to pre-collected map
        if ptr in name_map:
            return name_map[ptr]
    else:
        # Pointer to raw UTF-16LE data
        off = translate(ptr)
        if off is not None and off + length * 2 <= len(data):
            nb = data[off:off + length * 2]
            return nb.decode('utf-16-le', errors='replace').rstrip('\x00')

    return ""


def _ftl_read(data, translate, logical_addr, size):
    """Read `size` bytes starting at `logical_addr`, translating each page
    through the FTL independently.  This correctly handles reads that span
    physical page boundaries (including mapping-page gaps in erase blocks)."""
    result = bytearray()
    remaining = size
    la = logical_addr
    while remaining > 0:
        abs_off = translate(la)
        if abs_off is None:
            result.extend(b'\x00' * remaining)
            break
        page_remaining = 0x1000 - (la & 0xFFF)
        to_read = min(remaining, page_remaining)
        if abs_off + to_read > len(data):
            result.extend(b'\x00' * remaining)
            break
        result.extend(data[abs_off:abs_off + to_read])
        remaining -= to_read
        la += to_read
    return bytes(result)


def _read_index_data(data, translate, indexptr, indexsize, expected):
    """Read and decompress data via an index block."""
    if indexptr == 0 or indexsize == 0:
        return None

    # Read the index block itself page-by-page
    idx_raw = _ftl_read(data, translate, indexptr, indexsize)
    if len(idx_raw) < indexsize:
        return None

    result = bytearray()
    n_records = indexsize // 8

    for i in range(n_records):
        ro = i * 8
        comp_sz = u16(idx_raw, ro)
        full_sz = u16(idx_raw, ro + 2)
        ptr     = u32(idx_raw, ro + 4)

        if comp_sz == 0 and full_sz == 0 and ptr == 0:
            break

        if ptr == 0:
            result.extend(b'\x00' * full_sz)
            continue

        # Read chunk data page-by-page through FTL
        chunk = _ftl_read(data, translate, ptr, comp_sz)

        if comp_sz == full_sz:
            result.extend(chunk)
        else:
            dec = try_decompress(chunk, full_sz)
            if dec is not None:
                result.extend(dec)
            else:
                result.extend(chunk)
                result.extend(b'\x00' * (full_sz - comp_sz))

    return bytes(result[:expected]) if expected > 0 else bytes(result)


def extract_imgfs(data, output_dir):
    """
    Locate and extract all files from the IMGFS filesystem.
    Handles both FTL-mapped and direct-addressed (NOR) images.
    """
    # Find IMGFS superblock (page-aligned, valid header fields)
    imgfs_base = -1
    pos = 0
    while True:
        idx = data.find(IMGFS_UUID, pos)
        if idx == -1:
            break
        if idx % 0x1000 == 0:
            ds = u32(data, idx + 0x1C)
            bpb = u32(data, idx + 0x24)
            if ds == IMGFS_DIRENT_SIZE and 0x200 <= bpb <= 0x10000:
                imgfs_base = idx
                break
        pos = idx + 1

    if imgfs_base == -1:
        return

    direntsize  = u32(data, imgfs_base + 0x1C)
    bytesperblk = u32(data, imgfs_base + 0x24)
    ents_per_blk = (bytesperblk - 8) // direntsize

    print(f"  IMGFS at 0x{imgfs_base:08X} (block={bytesperblk})")

    # Build translation layer
    base_sector, mapping = build_ftl_mapping(data, imgfs_base)
    if base_sector is not None:
        translate = make_ftl_translate(imgfs_base, base_sector, mapping)
        print(f"  FTL: base_sector=0x{base_sector:X}, {len(mapping)} sectors")
    else:
        translate = make_direct_translate(imgfs_base, len(data))
        print(f"  Direct addressing (NOR flash)")

    # Scan for directory blocks
    dir_blocks = []
    for off in range(imgfs_base, len(data) - 8, bytesperblk):
        if u32(data, off) == IMGFS_DIR_MAGIC:
            dir_blocks.append(off)

    print(f"  {len(dir_blocks)} directory blocks")

    # Pre-collect NAME entries for fallback resolution
    name_map = {}  # logical_offset → name string
    for boff in dir_blocks:
        for i in range(ents_per_blk):
            eo = boff + 8 + i * direntsize
            if eo + direntsize > len(data):
                break
            if u32(data, eo) == MAGIC_NAME:
                nb = data[eo + 4:eo + 52]
                name = nb.decode('utf-16-le', errors='replace').rstrip('\x00')
                name_map[eo - imgfs_base] = name

    # Collect all directory entries (across all blocks) in order
    all_entries = []
    for boff in dir_blocks:
        for i in range(ents_per_blk):
            eo = boff + 8 + i * direntsize
            if eo + direntsize > len(data):
                break
            raw = data[eo:eo + direntsize]
            magic = u32(raw, 0)
            all_entries.append((eo, raw, magic))

    out_dir = os.path.join(output_dir, "Windows")
    os.makedirs(out_dir, exist_ok=True)

    files_ok = mods_ok = 0
    files_fail = mods_fail = 0

    def _valid_name(n):
        return n and len(n) <= 260 and all(32 <= ord(c) < 127 for c in n)

    i = 0
    while i < len(all_entries):
        eo, raw, magic = all_entries[i]

        if magic == MAGIC_FILE:
            nameinfo  = raw[0x0C:0x0C + 12]
            file_size = u32(raw, 0x18)
            indexptr  = u32(raw, 0x2C)
            indexsize = u32(raw, 0x30)

            name = _resolve_name(data, translate, nameinfo, name_map)
            if not _valid_name(name):
                name = f"unnamed_{eo - imgfs_base:06X}.dat"

            fdata = _read_index_data(data, translate, indexptr, indexsize, file_size)
            if fdata:
                path = os.path.join(out_dir, safe_filename(name))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'wb') as f:
                    f.write(fdata)
                files_ok += 1
            else:
                files_fail += 1
            i += 1

        elif magic == MAGIC_MODULE:
            nameinfo  = raw[0x0C:0x0C + 12]
            file_size = u32(raw, 0x18)
            indexptr  = u32(raw, 0x2C)
            indexsize = u32(raw, 0x30)

            name = _resolve_name(data, translate, nameinfo, name_map)
            if not _valid_name(name):
                name = f"unnamed_{eo - imgfs_base:06X}.dll"

            # Read module header (e32rom + o32_rom)
            header = _read_index_data(data, translate, indexptr, indexsize, file_size)

            # Walk adjacent SECTION entries (skip NAME entries)
            sec_data = {}
            j = i + 1
            while j < len(all_entries):
                _, sraw, smag = all_entries[j]
                if smag == MAGIC_NAME:
                    j += 1
                    continue
                if smag != MAGIC_SECTION:
                    break
                sni   = sraw[0x0C:0x0C + 12]
                ssz   = u32(sraw, 0x18)
                siptr = u32(sraw, 0x1C)
                sisz  = u32(sraw, 0x20)

                sname = _resolve_name(data, translate, sni, name_map)
                sd = _read_index_data(data, translate, siptr, sisz, ssz)
                if sd:
                    sec_data[sname] = sd
                j += 1

            wrote = False
            if sec_data and header:
                pe = reconstruct_pe_imgfs(header, sec_data)
                if pe:
                    path = os.path.join(out_dir, safe_filename(name))
                    with open(path, 'wb') as f:
                        f.write(pe)
                    wrote = True
                else:
                    # Save raw sections as fallback
                    mdir = os.path.join(out_dir, safe_filename(name) + ".sections")
                    os.makedirs(mdir, exist_ok=True)
                    with open(os.path.join(mdir, "_header.bin"), 'wb') as f:
                        f.write(header)
                    for sn, sd in sec_data.items():
                        sf = safe_filename(sn) if sn else "unknown"
                        with open(os.path.join(mdir, sf + ".bin"), 'wb') as f:
                            f.write(sd)
                    wrote = True
            elif sec_data:
                mdir = os.path.join(out_dir, safe_filename(name) + ".sections")
                os.makedirs(mdir, exist_ok=True)
                for sn, sd in sec_data.items():
                    sf = safe_filename(sn) if sn else "unknown"
                    with open(os.path.join(mdir, sf + ".bin"), 'wb') as f:
                        f.write(sd)
                wrote = True

            if wrote:
                mods_ok += 1
            else:
                mods_fail += 1

            i = j

        else:
            i += 1

    print(f"  IMGFS: {files_ok} files, {mods_ok} modules extracted")
    if files_fail or mods_fail:
        print(f"  ({files_fail} file failures, {mods_fail} module failures)")


# ── Main extraction pipeline ────────────────────────────────────────────────

def extract_image(bin_path):
    """Extract a Device Emulator ROM image."""
    print(f"Reading {bin_path}...")
    with open(bin_path, 'rb') as f:
        data = f.read()
    print(f"  {len(data)} bytes ({len(data) / 1024 / 1024:.1f} MB)")

    base_name = os.path.splitext(os.path.basename(bin_path))[0]
    out_dir = os.path.join(os.path.dirname(os.path.abspath(bin_path)), base_name)

    if os.path.exists(out_dir):
        print(f"Cleaning {out_dir}")
        shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    is_b000ff = data[:7] == b'B000FF\n'

    if is_b000ff:
        # ── B000FF container (WM5) ──
        print("\nFormat: B000FF (section container)")
        flat, base_va = parse_b000ff(data)
        if flat is None:
            print("ERROR: Failed to parse B000FF container")
            return False

        print("\nExtracting XIP regions...")
        extract_xip_regions(flat, base_va, out_dir)

    else:
        # ── NB0 flat image (WM6+) ──
        # Verify ARM branch at offset 0 (loadbin_nb0.cpp: 0xEA000000 mask)
        sig = u32(data, 0)
        if sig & 0xEA000000 != 0xEA000000:
            print(f"WARNING: Not a recognised format (sig=0x{sig:08X})")

        print("\nFormat: NB0 flat image")

        # Check for IMGFS
        has_imgfs = False
        pos = 0
        while True:
            idx = data.find(IMGFS_UUID, pos)
            if idx == -1:
                break
            if idx % 0x1000 == 0:
                ds = u32(data, idx + 0x1C)
                bpb = u32(data, idx + 0x24)
                if ds == IMGFS_DIRENT_SIZE and 0x200 <= bpb <= 0x10000:
                    has_imgfs = True
                    break
            pos = idx + 1

        print("\nExtracting XIP regions...")
        extract_xip_regions(data, 0, out_dir)

        if has_imgfs:
            print("\nExtracting IMGFS filesystem...")
            extract_imgfs(data, out_dir)

    # ── Post-process: create directory structure from initflashfiles.dat ──
    win_dir = os.path.join(out_dir, "Windows")
    if os.path.isdir(win_dir):
        import re as _re
        iff_path = os.path.join(win_dir, "initflashfiles.dat")
        if os.path.isfile(iff_path):
            with open(iff_path, 'rb') as f:
                raw = f.read()
            if raw[:2] == b'\xff\xfe':
                iff_text = raw[2:].decode('utf-16-le', errors='replace')
            else:
                iff_text = raw.decode('utf-16-le', errors='replace')
            iff_text = iff_text.replace('\r', '')

            def _decode_hex_name(s):
                """Decode \\x00XX hex sequences to characters."""
                def repl(m):
                    return chr(int(m.group(1), 16))
                return _re.sub(r'\\x([0-9A-Fa-f]{4})', repl, s)

            dirs_created = 0
            files_placed = 0

            for line in iff_text.split('\n'):
                line = line.strip()
                if not line or line.startswith(';'):
                    continue

                # Parse: Directory("path"):-Directory("name")
                m = _re.match(r'(?:root|[Dd]irectory\("([^"]*)"\))\s*:-\s*(?:Perm)?[Dd]irectory\("([^"]*)"\)', line)
                if m:
                    parent = m.group(1) or ''
                    child = _decode_hex_name(m.group(2))
                    if parent:
                        parent = parent.replace('\\\\', chr(92))
                        if not parent.startswith(chr(92)):
                            parent = chr(92) + parent
                        full = parent + chr(92) + child
                    else:
                        full = chr(92) + child
                    host = os.path.join(out_dir, full.lstrip(chr(92)).replace(chr(92), os.sep))
                    os.makedirs(host, exist_ok=True)
                    dirs_created += 1
                    continue

                # Parse: Directory("path"):-File("destname","srcpath")
                m = _re.match(r'[Dd]irectory\("([^"]*)"\)\s*:-\s*[Ff]ile\("([^"]*)",\s*"([^"]*)"\)', line)
                if m:
                    dest_dir = m.group(1).replace('\\\\', chr(92))
                    dest_name = _decode_hex_name(m.group(2))
                    src_path = m.group(3).replace('\\\\', chr(92))

                    if not dest_dir.startswith(chr(92)):
                        dest_dir = chr(92) + dest_dir

                    # Source file is in \Windows\ (our extraction root)
                    src_file = os.path.basename(src_path)
                    src_full = os.path.join(win_dir, src_file)

                    # Destination
                    dest_full_dir = os.path.join(out_dir, dest_dir.lstrip(chr(92)).replace(chr(92), os.sep))
                    os.makedirs(dest_full_dir, exist_ok=True)
                    dest_full = os.path.join(dest_full_dir, dest_name)

                    if os.path.isfile(src_full) and not os.path.exists(dest_full):
                        shutil.copy2(src_full, dest_full)
                        files_placed += 1

            print(f"\nDirectory structure (from initflashfiles.dat):")
            print(f"  {dirs_created} directories created")
            print(f"  {files_placed} files placed")

    # ── Post-process: organize registry files ──
    reg_dir = os.path.join(out_dir, "Registry")
    if os.path.isdir(win_dir):
        rgu_files = sorted(f for f in os.listdir(win_dir)
                           if f.lower().endswith('.rgu'))
        hv_files = [f for f in os.listdir(win_dir)
                    if f.lower().endswith('.hv')]

        if rgu_files or hv_files:
            os.makedirs(reg_dir, exist_ok=True)
            print(f"\nRegistry files:")

            # Convert .rgu files from UTF-16LE to UTF-8 .reg files
            for rgu in rgu_files:
                src = os.path.join(win_dir, rgu)
                reg_name = os.path.splitext(rgu)[0] + '.reg'
                dst = os.path.join(reg_dir, reg_name)
                try:
                    with open(src, 'rb') as f:
                        raw = f.read()
                    if raw[:2] == b'\xff\xfe':
                        text = raw[2:].decode('utf-16-le', errors='replace')
                    else:
                        text = raw.decode('utf-16-le', errors='replace')
                    # Normalize line endings: strip \r, write with system newlines
                    text = text.replace('\r\n', '\n').replace('\r', '\n')
                    with open(dst, 'w', encoding='utf-8') as f:
                        f.write(text)
                except Exception:
                    shutil.copy2(src, dst)

            # Copy .hv hive files
            for hv in hv_files:
                shutil.copy2(os.path.join(win_dir, hv),
                             os.path.join(reg_dir, hv))

            print(f"  {len(rgu_files)} .reg files -> {reg_dir} (UTF-8)")
            print(f"  {len(hv_files)} .hv hive files -> {reg_dir}")

    print(f"\nDone -> {out_dir}")
    return True


def main():
    if len(sys.argv) > 1:
        paths = sys.argv[1:]
    else:
        # Auto-detect .BIN and .nb0 files in current directory
        here = os.path.dirname(os.path.abspath(__file__))
        paths = sorted(
            os.path.join(here, f)
            for f in os.listdir(here)
            if f.upper().endswith(('.BIN', '.NB0')) and os.path.isfile(os.path.join(here, f))
        )
        if not paths:
            print("Usage: python extract_wince_rom.py <image.BIN|.nb0> [...]")
            print("   or: place .BIN/.nb0 files next to this script")
            sys.exit(1)

    for p in paths:
        if not os.path.isfile(p):
            print(f"ERROR: Not found: {p}")
            continue
        print("=" * 60)
        extract_image(p)
        print()


if __name__ == '__main__':
    main()
