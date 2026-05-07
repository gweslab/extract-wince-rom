"""B000FF container parsing (Microsoft Device Emulator format)."""

from .util import u32, SECTION_HEADER_SIZE


def parse_b000ff(data):
    """Parse a B000FF container image into a flat VA-indexed byte array.

    Format (from Device Emulator loadbin_nb0.cpp):
      - 7 bytes  : "B000FF\\n"
      - 4 bytes  : image start address
      - 4 bytes  : image length
      - sections : each = 12-byte CESectionHeader + fSectionSize bytes of data
      - terminator: section with fSectionBaseAddress == 0

    Returns (flat, min_va, records) or (None, None, None) on failure.
    `records` is a list of (base_va, size, file_offset) tuples for each section,
    so the caller can dump them verbatim if desired.
    """
    if data[:7] != b'B000FF\n':
        return None, None, None

    off = 15  # skip sig (7) + addr (4) + len (4)

    records = []
    while off + SECTION_HEADER_SIZE <= len(data):
        base = u32(data, off)
        size = u32(data, off + 4)
        # checksum at off+8, ignored for extraction
        data_off = off + SECTION_HEADER_SIZE
        # Terminator: an empty record OR a record whose 'size' overshoots the
        # file (the canonical kernel-ROM EOF marker has base=0 and reuses 'size'
        # to carry the entry point, which is always larger than the file).
        if base == 0 and size == 0:
            break
        if data_off + size > len(data) or size > 0x10000000:
            break
        records.append((base, size, data_off))
        off = data_off + size

    if not records:
        return None, None, None

    min_va = min(r[0] for r in records)
    max_end = max(r[0] + r[1] for r in records)
    flat = bytearray(max_end - min_va)
    for addr, length, file_off in records:
        flat[addr - min_va:addr - min_va + length] = data[file_off:file_off + length]

    print(f"  B000FF: {len(records)} sections, VA range "
          f"0x{min_va:08X}..0x{max_end:08X} ({len(flat) / 1024:.0f} KB)")
    return bytes(flat), min_va, records
