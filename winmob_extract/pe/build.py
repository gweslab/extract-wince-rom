"""PE32 assembly: take parsed e32rom fields + section list, emit a PE file.

Pure formatter - no logic about where the data came from. Inputs are
already-decoded numbers and section dicts.
"""

import struct

from ..util import align


# CE data-directory indices -> PE data-directory indices
CE_TO_PE_DD = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 12, 8: 14}


def section_name(flags, rva, ce_dds, vsize=None):
    """Infer PE section name from o32 flags and data-directory hits.

    When two o32 records share an RVA (a ROM-image overlay layout where
    a writable RAM-loaded section and a read-only XIP section share a
    PE-RVA window), require the section's vsize to match the DD's size
    before claiming the directory's name. Without this, a .data overlay
    sharing RVA with .pdata would be mis-named .pdata."""
    for idx, (dd_rva, dd_sz) in enumerate(ce_dds):
        if dd_rva == rva and dd_sz > 0:
            if vsize is not None and vsize != dd_sz:
                continue
            if idx == 2:
                return b'.rsrc\x00\x00\x00'
            if idx == 3:
                return b'.pdata\x00\x00'
            if idx == 5:
                return b'.reloc\x00\x00'
    if flags & 0x20:
        return b'.text\x00\x00\x00'
    if flags & 0x80:
        return b'.bss\x00\x00\x00\x00'
    if flags & 0x40:
        return b'.data\x00\x00\x00' if flags & 0x80000000 else b'.rdata\x00\x00'
    return b'.sec\x00\x00\x00\x00'


def build_pe(objcnt, imgflags, entry_rva, vbase, subsys_maj, subsys_min,
             stackmax, vsize, timestamp, ce_dds, sections, machine,
             subsystem=9, sect14_rva=0, sect14_size=0):
    """Assemble a PE32 file from parsed e32rom fields and raw section data.

    Most fields come from the e32rom header. A few that ROMs strip get
    canonical defaults; some are keyed off `subsys_maj` (the source PE's
    MajorSubsystemVersion, which the binary itself reports):

      - OSMajor / OSMinor      : 4/0 if sub_maj < 7, else (sub_maj, sub_min)
      - FileAlignment          : 0x200 if sub_maj < 7, else 0x1000
      - DllCharacteristics     : NX_COMPAT (0x0100) if sub_maj >= 6, else 0
      - StackCommit            : 0x1000
      - HeapReserve / Commit   : 0x100000 / 0x1000

    sections: list of dicts {name, vsize, rva, raw_size, flags, data}
    ce_dds:   list of (rva, size) for 9 CE data directories
    """
    SA = 0x1000
    FA = 0x1000 if subsys_maj >= 7 else 0x200
    PE_DDS = 16

    os_maj = subsys_maj if subsys_maj >= 7 else 4
    os_min = subsys_min if subsys_maj >= 7 else 0
    dll_chars = 0x0100 if subsys_maj >= 6 else 0

    stk_commit = 0x1000
    heap_reserve = 0x100000
    heap_commit = 0x1000

    dos_sz = 64
    pe_sig_sz = 4
    coff_sz = 20
    opt_sz = 224  # PE32: 96 fixed + 16*8 data-dirs
    sechdr_sz = len(sections) * 40

    hdr_raw = dos_sz + pe_sig_sz + coff_sz + opt_sz + sechdr_sz
    hdr_aligned = align(hdr_raw, FA)

    foff = hdr_aligned
    for s in sections:
        s['foff'] = foff
        s['raw_a'] = align(s['raw_size'], FA) if s['raw_size'] > 0 else 0
        foff += s['raw_a']

    # SizeOfImage: last section RVA + section-aligned vsize
    if sections:
        last = sections[-1]
        size_of_image = align(last['rva'] + last['vsize'], SA)
    else:
        size_of_image = align(hdr_aligned, SA)

    pe = bytearray(foff)

    # DOS header
    pe[0:2] = b'MZ'
    struct.pack_into('<I', pe, 0x3C, dos_sz)

    # PE signature
    p = dos_sz
    pe[p:p + 4] = b'PE\x00\x00'
    p += 4

    # COFF header (Characteristics: imgflags from e32rom + force EXECUTABLE_IMAGE)
    chars = imgflags | 0x0002
    struct.pack_into('<HHIIIHH', pe, p,
                     machine, len(sections), timestamp, 0, 0, opt_sz, chars)
    p += coff_sz

    # Optional header (PE32). All fields from e32rom or computed.
    o = p
    code_sz   = sum(s['raw_a'] for s in sections if s['flags'] & 0x20)
    idata_sz  = sum(s['raw_a'] for s in sections if s['flags'] & 0x40)
    udata_sz  = sum(s['vsize'] for s in sections if s['flags'] & 0x80)
    base_code = sections[0]['rva'] if sections else SA
    base_data = next((s['rva'] for s in sections if s['flags'] & 0x40), 0)

    struct.pack_into('<H', pe, o, 0x10B)              # +0  Magic = PE32
    struct.pack_into('<III', pe, o + 4, code_sz, idata_sz, udata_sz)
    struct.pack_into('<I',  pe, o + 16, entry_rva)     # +16 AddressOfEntryPoint
    struct.pack_into('<I',  pe, o + 20, base_code)     # +20 BaseOfCode
    struct.pack_into('<I',  pe, o + 24, base_data)     # +24 BaseOfData
    struct.pack_into('<I',  pe, o + 28, vbase)         # +28 ImageBase
    struct.pack_into('<II', pe, o + 32, SA, FA)        # +32 SectionAlignment, FileAlignment
    struct.pack_into('<HH', pe, o + 40, os_maj, os_min)         # +40 OS Major/Minor
    struct.pack_into('<HH', pe, o + 48, subsys_maj, subsys_min) # +48 SubsystemMajor/Minor
    struct.pack_into('<II', pe, o + 56, size_of_image, hdr_aligned)  # +56/60 SizeOfImage / SizeOfHeaders
    struct.pack_into('<H',  pe, o + 68, subsystem)     # +68 Subsystem
    struct.pack_into('<H',  pe, o + 70, dll_chars)     # +70 DllCharacteristics
    struct.pack_into('<I',  pe, o + 72, stackmax)      # +72 SizeOfStackReserve
    struct.pack_into('<I',  pe, o + 76, stk_commit)    # +76 SizeOfStackCommit
    struct.pack_into('<I',  pe, o + 80, heap_reserve)  # +80 SizeOfHeapReserve
    struct.pack_into('<I',  pe, o + 84, heap_commit)   # +84 SizeOfHeapCommit
    struct.pack_into('<I',  pe, o + 92, PE_DDS)        # +92 NumberOfRvaAndSizes

    # Data directories: map CE e32_unit[0..8] to PE DataDirectory[0..15]
    dd_base = o + 96
    for ce_i, (dd_rva, dd_sz) in enumerate(ce_dds):
        pe_i = CE_TO_PE_DD.get(ce_i)
        if pe_i is not None and dd_rva:
            struct.pack_into('<II', pe, dd_base + pe_i * 8, dd_rva, dd_sz)
    # e32_sect14rva/size -> DataDirectory[14] (CLR/RS4)
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
