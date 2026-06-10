"""rom_meta.json assembly: initial state, kernel identification, and emit.

The region extractor populates the dict returned by _new_rom_meta as it walks
each XIP region; _write_rom_meta finalizes (kernel binary + romhdr_va) and
serializes it, stripping the internal scratch keys (leading underscore).
"""

import json
import os


def _new_rom_meta():
    """Initial empty rom_meta state. Populated as extraction progresses."""
    return {
        'kernel_binary':    '',
        'romhdr_va':        '',
        'romhdr':           None,
        'rompid':           [],
        'copy_table':       [],
        'modules':          [],
        'files':            [],
        # Internal scratch (stripped before emit):
        '_romhdr_va_raw':   0,    # u32 at ECEC+4
        '_romhdr_off':      0,    # u32 at ECEC+8
        '_module_ranges':   [],   # (dataptr, psize) for every module's o32
                                  # records; used to compute the
                                  # Sections/ complement
        '_region_count':    0,    # number of XIP regions whose ROMHDR parsed
    }


_KERNEL_NAMES = ('nk.exe', 'kern.exe', 'kernel.dll')


def _finalize_rom_meta(rom_meta):
    """Identify the kernel binary and emit `romhdr_va` from the value at
    ECEC+4. Same code path for CE3 / CE5 / CE6 / CE7 - romimage writes
    the same field across versions, even though CE3's romldr.h does not
    define ROM_TOC_POINTER_OFFSET formally.

    Cross-check: when ECEC+8 (ROM_TOC_OFFSET_OFFSET) is non-zero, it
    must agree with ECEC+4 via `physfirst + (ECEC+8) == ECEC+4`. CE3
    ROMs don't populate ECEC+8 reliably, so the check is gated on
    non-zero."""
    for m in rom_meta['modules']:
        if m['name'].lower() in _KERNEL_NAMES:
            rom_meta['kernel_binary'] = m['name']
            break
    else:
        # No kernel module across any region. For a multi-module OS image that
        # is almost always an extraction failure, not a valid result, so emit a
        # loud warning.
        if rom_meta['modules']:
            n_regions = rom_meta.get('_region_count', 1)
            print(f"  WARNING: no kernel module found across "
                  f"{n_regions} region(s) ({len(rom_meta['modules'])} modules)")

    raw_va = rom_meta.get('_romhdr_va_raw', 0)
    if not raw_va:
        return

    romhdr_off = rom_meta.get('_romhdr_off', 0)
    if romhdr_off and rom_meta['romhdr']:
        physfirst = int(rom_meta['romhdr']['physfirst'], 16)
        derived = (physfirst + romhdr_off) & 0xFFFFFFFF
        if derived != raw_va:
            print(f"  WARNING: ECEC+4 (0x{raw_va:08X}) != "
                  f"physfirst+ECEC+8 (0x{derived:08X})")

    rom_meta['romhdr_va'] = f'0x{raw_va:08X}'


def _write_rom_meta(out_dir, rom_meta):
    """Emit rom_meta.json at the top of the extraction directory."""
    if not rom_meta or not rom_meta.get('romhdr'):
        return
    _finalize_rom_meta(rom_meta)
    out = {k: v for k, v in rom_meta.items() if not k.startswith('_')}
    path = os.path.join(out_dir, 'rom_meta.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2)
    print(f"  rom_meta ({len(out['modules'])} modules, "
          f"{len(out['files'])} files) -> {path}")
