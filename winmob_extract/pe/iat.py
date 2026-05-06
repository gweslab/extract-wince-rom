"""IAT repair: undo ROM-time bind resolution.

In a CE ROM, the loader has pre-resolved each module's IAT (Import Address
Table) to the absolute kernel addresses of imported functions. That means
the IAT bytes in the ROM image are not the standard `hint/name` ordinals a
PE loader expects to find - they're already-bound function pointers.

To produce a valid PE, we copy the ILT (Import Lookup Table - the
unresolved hint/name pointers) over the IAT, restoring its original
contents. This makes the emitted PE bind-able by any normal PE loader.
"""

import struct


def fix_iat_from_ilt(pe_data):
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

    # Build RVA -> file offset map from section table
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
                struct.pack_into('<I', pe, iat_pos, 0)
                break
            struct.pack_into('<I', pe, iat_pos, val)
            i += 1

    return bytes(pe)
