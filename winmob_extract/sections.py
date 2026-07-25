"""Sections/ emission: kernel-VA byte ranges of the ROM image.

'non-module' emits the complement of the per-module dataptr ranges
(bootloader, ROMHDR / TOC / FILESentry / COPYentry / ROMPID structures,
IMGFS region, strings, padding); 'full' emits the native container
layout.
"""

import os


def _rom_va_span(fmt, rom_meta, b000ff_records, nb0_data, nb0_load_offset):
    """Return (lo, hi) - the kernel-VA range the ROM spans. None if
    unknown."""
    hdr = rom_meta.get('romhdr') or {}
    physfirst = int(hdr.get('physfirst', '0x0'), 16)
    physlast  = int(hdr.get('physlast',  '0x0'), 16)
    if physfirst and physlast and physlast > physfirst:
        return physfirst, physlast
    if fmt == 'b000ff' and b000ff_records:
        load_offset = rom_meta.get('_load_offset', 0)
        flat_base_va = min(r[0] for r in b000ff_records)
        va_shift = load_offset - flat_base_va
        lo = min(r[0] for r in b000ff_records) + va_shift
        hi = max(r[0] + r[1] for r in b000ff_records) + va_shift
        return lo, hi
    if fmt == 'nb0' and nb0_data is not None and nb0_load_offset is not None:
        return nb0_load_offset, nb0_load_offset + len(nb0_data)
    return None, None


def _range_complement(lo, hi, ranges):
    """Return list of (start, end) covering [lo, hi) minus the union of
    `ranges`. `ranges` need not be sorted or merged."""
    if lo >= hi:
        return []
    if not ranges:
        return [(lo, hi)]
    sorted_ranges = sorted(ranges)
    merged = [list(sorted_ranges[0])]
    for s, e in sorted_ranges[1:]:
        if s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out = []
    cur = lo
    for s, e in merged:
        if e <= cur:
            continue
        if s > cur:
            out.append((cur, min(s, hi)))
        cur = max(cur, e)
        if cur >= hi:
            break
    if cur < hi:
        out.append((cur, hi))
    return out



def emit_sections(out_dir, sections_mode, rom_meta, fmt, *,
                   b000ff_data=None, b000ff_records=None,
                   nb0_data=None, nb0_load_offset=None):
    """Write Sections/ files. `sections_mode` is 'full', 'non-module', or 'no'.

    full: B000FF -> one file per ROM section (preserved native layout);
          NB0   -> one file with the whole flat image.
    non-module: emit only the byte ranges consumers need without
          fs/ - shared-RVA module sections + the IMGFS region.
    no: skip the Sections/ folder entirely.
    """
    if sections_mode == 'no':
        return
    sec_dir = os.path.join(out_dir, "Sections")
    os.makedirs(sec_dir, exist_ok=True)

    # B000FF records sometimes carry physical VAs (no high bit) while ECEC
    # / o32 carry kernel-VA (high bit set). Normalize record bases to
    # kernel-VA using the load_offset that extract_xip_regions discovered
    # from ECEC, so file names and shared-RVA dataptr intersections both
    # operate in the same VA space.
    va_shift = 0
    if fmt == 'b000ff' and b000ff_records:
        load_offset = rom_meta.get('_load_offset', 0)
        flat_base_va = min(r[0] for r in b000ff_records)
        va_shift = load_offset - flat_base_va

    if sections_mode == 'full':
        if fmt == 'b000ff':
            for i, (sec_base, sec_size, file_off) in enumerate(b000ff_records):
                kva = sec_base + va_shift
                path = os.path.join(
                    sec_dir, f"{i:02d}_0x{kva:08X}_{sec_size}.bin")
                with open(path, 'wb') as f:
                    f.write(b000ff_data[file_off:file_off + sec_size])
            print(f"  {len(b000ff_records)} sections dumped -> {sec_dir}")
        else:  # nb0
            path = os.path.join(
                sec_dir, f"00_0x{nb0_load_offset:08X}_{len(nb0_data)}.bin")
            with open(path, 'wb') as f:
                f.write(nb0_data)
            print(f"  1 section dumped -> {sec_dir}")
        return

    # 'non-module' = the complement of module dataptr ranges
    # within the ROM's kernel-VA span. Per-module bytes (every o32_rom
    # record's psize bytes at dataptr) are now reachable via the PE
    # container in fs/Windows/<name> and its embedded `.cerom` section -
    # consumers don't need them in Sections/. What's left in [physfirst,
    # physlast] is "everything not in a module": bootloaders, ROMHDR /
    # TOC / FILESentry / COPYentry / ROMPID kernel structures, the
    # IMGFS region (when present), strings, padding.
    rom_lo, rom_hi = _rom_va_span(fmt, rom_meta, b000ff_records,
                                  nb0_data, nb0_load_offset)
    if rom_lo is None:
        print(f"  Sections/ empty (no ROM VA span)")
        return

    module_ranges = sorted(
        (dp, dp + sz) for dp, sz in rom_meta.get('_module_ranges', [])
        if sz > 0
    )
    needed = _range_complement(rom_lo, rom_hi, module_ranges)

    if not needed:
        print(f"  Sections/ empty (every byte covered by a module PE)")
        return

    merged = [list(r) for r in needed]

    written = 0
    for s, e in merged:
        if fmt == 'b000ff':
            for sec_base, sec_size, file_off in b000ff_records:
                kva = sec_base + va_shift
                sec_end_kva = kva + sec_size
                ov_start = max(s, kva)
                ov_end = min(e, sec_end_kva)
                if ov_end > ov_start:
                    length = ov_end - ov_start
                    src_off_start = file_off + (ov_start - kva)
                    path = os.path.join(
                        sec_dir,
                        f"{written:02d}_0x{ov_start:08X}_{length}.bin")
                    with open(path, 'wb') as f:
                        f.write(b000ff_data[src_off_start:src_off_start + length])
                    written += 1
        else:  # nb0
            src_off_start = s - nb0_load_offset
            if src_off_start < 0 or src_off_start >= len(nb0_data):
                continue
            length = min(e - nb0_load_offset, len(nb0_data)) - src_off_start
            if length <= 0:
                continue
            path = os.path.join(
                sec_dir, f"{written:02d}_0x{s:08X}_{length}.bin")
            with open(path, 'wb') as f:
                f.write(nb0_data[src_off_start:src_off_start + length])
            written += 1
    print(f"  {written} sections dumped -> {sec_dir}")

