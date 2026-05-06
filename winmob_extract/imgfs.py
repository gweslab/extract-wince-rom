"""IMGFS filesystem extraction.

Locates the IMGFS superblock by UUID, builds a Flash Translation Layer
mapping (or direct addressing for NOR flash), walks directory blocks, and
emits files / reconstructed PE modules.
"""

import os
import struct

from .util import u16, u32, safe_filename
from .compress import try_decompress
from .pe import reconstruct_pe_imgfs


# IMGFS constants
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


# ── FTL (Flash Translation Layer) ───────────────────────────────────────────

def build_ftl_mapping(data, imgfs_base):
    """Build logical-sector -> physical-page mapping from NAND erase-block
    mapping tables.

    Each 64 KB erase block has 15 data pages (4 KB) + 1 mapping page.
    The mapping page contains 15 x 8-byte entries:
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
                continue
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
    """Return a function: IMGFS logical address -> absolute file offset."""
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
    through the FTL independently. This correctly handles reads that span
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


def find_imgfs_base(data):
    """Locate the IMGFS superblock (page-aligned, valid header fields).
    Returns offset or -1."""
    pos = 0
    while True:
        idx = data.find(IMGFS_UUID, pos)
        if idx == -1:
            return -1
        if idx % 0x1000 == 0:
            ds = u32(data, idx + 0x1C)
            bpb = u32(data, idx + 0x24)
            if ds == IMGFS_DIRENT_SIZE and 0x200 <= bpb <= 0x10000:
                return idx
        pos = idx + 1


def extract_imgfs(data, output_dir):
    """Locate and extract all files from the IMGFS filesystem.
    Handles both FTL-mapped and direct-addressed (NOR) images."""
    imgfs_base = find_imgfs_base(data)
    if imgfs_base == -1:
        return

    direntsize  = u32(data, imgfs_base + 0x1C)
    bytesperblk = u32(data, imgfs_base + 0x24)
    ents_per_blk = (bytesperblk - 8) // direntsize

    print(f"  IMGFS at 0x{imgfs_base:08X} (block={bytesperblk})")

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
    name_map = {}  # logical_offset -> name string
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
