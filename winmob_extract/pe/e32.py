"""e32rom header parsing and DD-layout auto-detection.

The e32_rom struct has two known variants in the wild:

  - 'legacy'   : data directory array starts at 0x20.
  - 'extended' : an extra 4-byte field of unverified meaning sits at
                 0x20 (preserved verbatim and emitted as the output
                 PE's COFF TimeDateStamp), pushing the DD array to 0x24.

The right variant is detected per-module by parsing both candidates and
picking the one whose DDs and subsystem look semantically valid.
"""

from ..util import u16, u32


E32_DD_OFF_LEGACY = 0x20
E32_DD_OFF_WM5    = 0x24  # name kept for back-compat; actual layout = "extended"
E32_DD_OFF_CE2    = 0x1C  # CE 2.11: e32_vsize at 0x14, e32_subsys (u16) at 0x18,
                          # DD array at 0x1C, no e32_sect14 field (added in CE3).
E32_DD_OFF_CE20   = 0x18  # CE 2.0: e32_rom has no e32_vsize field (added in
                          # CE 2.11). e32_subsys (u16) occupies 0x14 and the DD
                          # array follows at 0x18; vsize is derived from the
                          # o32_rom records by the caller. Grounded in the
                          # CE 2.11 romldr.h e32_rom struct (which lists
                          # e32_vsize as a distinct field) plus cross-module
                          # validation of a MIPS CE 2.0 ROM (coredll's DD[0]
                          # export directory lands at 0x18).
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

    if dd_offset == E32_DD_OFF_CE20:
        # CE 2.0: no e32_vsize field. e32_subsys (u16) is at 0x14, the DD
        # array at 0x18, no e32_sect14 field or timestamp. vsize is left 0
        # here as a sentinel; the caller derives it from the o32_rom records.
        vsize = 0
        subsys = u16(data, off + 0x14)
        sect14_rva = 0
        sect14_size = 0
        ts = 0
    elif dd_offset == E32_DD_OFF_CE2:
        # CE 2.11: e32_vsize at 0x14, e32_subsys sits at 0x18 (before the DD
        # array), the DD array at 0x1C, no e32_sect14 field or timestamp.
        vsize = u32(data, off + 0x14)
        subsys = u16(data, off + 0x18)
        sect14_rva = 0
        sect14_size = 0
        ts = 0
    else:
        vsize = u32(data, off + 0x14)
        # The extended layout has a 4-byte field at +0x20 the legacy layout
        # lacks (legacy puts DD[0] there instead). Semantics unverified;
        # preserved verbatim into the output COFF TimeDateStamp.
        ts = u32(data, off + 0x20) if dd_offset == E32_DD_OFF_WM5 else 0
        # e32_subsys is at offset dd_offset+72 (after the 9 data dirs).
        subsys_off = dd_offset + 72
        subsys = u16(data, off + subsys_off) if off + subsys_off + 2 <= len(data) else 9
        sect14_rva = u32(data, off + 0x18)
        sect14_size = u32(data, off + 0x1C)

    ce_dds = []
    for i in range(9):
        d = off + dd_offset + i * 8
        ce_dds.append((u32(data, d), u32(data, d + 4)))

    return dict(objcnt=objcnt, imgflags=imgflags, entry_rva=entry_rva,
                vbase=vbase, sub_maj=sub_maj, sub_min=sub_min,
                stackmax=stackmax, vsize=vsize, timestamp=ts, ce_dds=ce_dds,
                subsystem=subsys, sect14_rva=sect14_rva, sect14_size=sect14_size,
                is_ce20=(dd_offset == E32_DD_OFF_CE20))


def _layout_valid(info):
    """Strict validity check on a parsed layout. Rejects values that
    can't come from a real PE - DD RVAs in the header region, sizes
    exceeding image bounds, etc. - so the auto-detector can tell
    apart legacy and extended on a per-module basis."""
    if info is None:
        return False
    # Standard IMAGE_SUBSYSTEM values seen in CE modules; used as a
    # layout discriminator (a wrong dd_offset lands "subsystem" on garbage).
    # CE 2.0 additionally admits 4: the separately-built MFC/OLE-for-CE
    # component DLLs stamp a nonstandard e32_subsys=4 (their subsysmajor is
    # likewise 4, tracking MFC's version, not the OS's). Safe to admit only
    # here because the DD page-alignment score is the real CE2.0 discriminator.
    ok_subsys = (1, 2, 3, 4, 7, 9, 10, 11) if info.get('is_ce20') else (1, 2, 3, 7, 9, 10, 11)
    if info['subsystem'] not in ok_subsys:
        return False
    vsize = info['vsize']
    if info.get('is_ce20'):
        # CE 2.0 has no e32_vsize; it is derived from o32 later. The DD RVAs
        # are bounded loosely here (subsystem validity above is the layout
        # discriminator vs. the CE 2.11 / legacy / extended candidates).
        bound = 0x10000000
    else:
        if vsize == 0 or vsize > 0x10000000:
            return False
        bound = vsize
    for rva, sz in info['ce_dds']:
        if rva and rva >= bound:
            return False
        if sz and sz > bound:
            return False
        if rva and sz and rva + sz > bound + 0x1000:  # allow small header slop
            return False
        # Real DDs sit in their own sections, never inside the PE header.
        # When parsing with the wrong dd_offset, RVAs shift to (prev_sz)
        # and frequently land below 0x100.
        if rva and rva < 0x100:
            return False
    return True


def _layout_score(info):
    """Tie-breaker score: how plausible does this layout look?

    Page-aligned DD RVAs are a strong signal: BASERELOC, IMPORT,
    EXCEPTION, DEBUG, etc. live at the start of their own sections,
    so their RVAs are usually 0x1000-aligned. The wrong dd_offset
    shifts RVAs into mid-section sizes, which are almost never aligned."""
    if info is None:
        return -1
    score = 0
    for rva, sz in info['ce_dds']:
        if rva and (rva & 0xFFF) == 0:
            score += 2
        if rva and sz:
            score += 1
    return score


def parse_e32_auto(data, off):
    """Detect e32rom DD layout. Try both, pick the higher-scoring valid one.
    Returns (info, dd_offset) or (None, None)."""
    candidates = []
    info_wm5 = parse_e32_base(data, off, E32_DD_OFF_WM5)
    if _layout_valid(info_wm5):
        candidates.append((_layout_score(info_wm5), info_wm5, E32_DD_OFF_WM5))
    info_leg = parse_e32_base(data, off, E32_DD_OFF_LEGACY)
    if _layout_valid(info_leg):
        candidates.append((_layout_score(info_leg), info_leg, E32_DD_OFF_LEGACY))
    info_ce2 = parse_e32_base(data, off, E32_DD_OFF_CE2)
    if _layout_valid(info_ce2):
        candidates.append((_layout_score(info_ce2), info_ce2, E32_DD_OFF_CE2))
    # CE 2.0 last: mutually exclusive with the others by e32_subsys offset, so
    # it only wins when the newer layouts are invalid (a genuine CE 2.0 module).
    info_ce20 = parse_e32_base(data, off, E32_DD_OFF_CE20)
    if _layout_valid(info_ce20):
        candidates.append((_layout_score(info_ce20), info_ce20, E32_DD_OFF_CE20))
    if not candidates:
        return None, None
    # Highest score wins; on tie, WM5 wins (newer layout, listed first).
    candidates.sort(key=lambda c: -c[0])
    _, info, off_used = candidates[0]
    return info, off_used
