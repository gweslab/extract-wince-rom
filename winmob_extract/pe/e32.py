"""e32rom header parsing and DD-layout auto-detection.

The e32_rom struct has two known variants in CE / Windows Mobile ROMs:

  - 'legacy' (CE3 / WM2003): data directory array starts at 0x20.
  - WM5+-style              : an extra 4-byte field of unverified meaning sits
                              at 0x20 (preserved verbatim and emitted as the
                              output PE's COFF TimeDateStamp), pushing the DD
                              array to 0x24.

The right variant is detected per-module by parsing both candidates and
picking the one whose DDs and subsystem look semantically valid.
"""

from ..util import u16, u32


E32_DD_OFF_LEGACY = 0x20  # CE3 / WM2003
E32_DD_OFF_WM5    = 0x24  # WM5+-style
O32_SIZE = 24             # sizeof(o32_rom)


def parse_e32_base(data, off, dd_offset):
    """Parse common e32rom fields. Returns dict or None if out of bounds."""
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
    # WM5+ e32rom has a 4-byte field at offset 0x20 that the CE3/WM2003 (legacy)
    # layout lacks (in the legacy layout, DD[0] sits there instead). Empirically
    # the value is sometimes a Unix timestamp matching the build date, but more
    # often is unrecognizable (likely a compiler-generated hash). Semantic meaning
    # is unverified; preserved verbatim and emitted into the output COFF TimeDateStamp.
    ts = u32(data, off + 0x20) if dd_offset == E32_DD_OFF_WM5 else 0

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


def _layout_valid(info):
    """Heuristic: does this parse look semantically right? Catches DD offset
    mismatches between CE3/WM2003 (legacy) and WM5+-style layouts."""
    if info is None:
        return False
    if info['subsystem'] not in (1, 2, 3, 7, 9, 10, 11):
        return False
    vsize = info['vsize']
    if vsize == 0 or vsize > 0x10000000:
        return False
    for rva, sz in info['ce_dds']:
        if rva and rva >= vsize:
            return False
        if sz and sz > vsize:
            return False
        if rva and sz and rva + sz > vsize + 0x1000:  # allow small header slop
            return False
    return True


def parse_e32_auto(data, off):
    """Detect e32rom DD layout by parsing both candidates and picking the one
    whose DDs and subsystem make sense. Returns (info, dd_offset) or (None, None)."""
    info = parse_e32_base(data, off, E32_DD_OFF_WM5)
    if _layout_valid(info):
        return info, E32_DD_OFF_WM5
    info = parse_e32_base(data, off, E32_DD_OFF_LEGACY)
    if _layout_valid(info):
        return info, E32_DD_OFF_LEGACY
    return None, None
