"""Top-level extraction pipeline:
    1. Read ROM image (.BIN B000FF, .nb0 flat)
    2. Walk XIP regions -> emit reconstructed PE files into <out>/Windows/
    3. (NB0 only) Walk IMGFS filesystem -> emit files / modules
    4. Post-process: rebuild directory tree from initflashfiles.dat / initobj.dat
    5. Post-process: convert registry blobs (.rgu / .hv / default.fdf) into <out>/Registry/
    6. Emit rom_meta.json with ROMHDR fields, module/file inventory, romhdr_va
"""

import json
import os
import re
import shutil

from .util import u32
from .b000ff import parse_b000ff
from .xip import extract_xip_regions
from .imgfs import IMGFS_UUID, find_imgfs_base, extract_imgfs
from .registry import CE_FDF_MAGIC, parse_fdf_registry, fdf_to_reg_text


# ── Directory structure (initflashfiles.dat / initobj.dat) ──────────────────

def _decode_hex_name(s):
    """Decode \\x00XX hex sequences to characters."""
    return re.sub(r'\\x([0-9A-Fa-f]{4})',
                  lambda m: chr(int(m.group(1), 16)), s)


def _post_process_fs(fs_dir, win_dir, attr_log=None):
    """Rebuild directory tree from initflashfiles.dat (WM5+) or
    initobj.dat (CE3 / WM2003). Same syntax in all of them.

    Files are placed under `fs_dir` (typically `<out>/fs/`) so the
    bundled filesystem stays separate from `<out>/Registry/`,
    `<out>/Sections/`, `<out>/attributes.ini`, `<out>/rom_meta.json`.

    If attr_log is given (mapping '\\Windows\\<name>' -> (attrs, filetime)),
    each placed file gets an additional entry under its placed CE path so
    the emulator has attrs at every on-disk location."""
    iff_path = None
    iff_source = None
    for candidate in ("initflashfiles.dat", "initobj.dat"):
        p = os.path.join(win_dir, candidate)
        if os.path.isfile(p):
            iff_path = p
            iff_source = candidate
            break
    if not iff_path:
        return

    with open(iff_path, 'rb') as f:
        raw = f.read()
    if raw[:2] == b'\xff\xfe':
        text = raw[2:].decode('utf-16-le', errors='replace')
    else:
        text = raw.decode('utf-16-le', errors='replace')
    text = text.replace('\r', '')

    dirs_created = 0
    files_placed = 0

    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith(';'):
            continue

        # Directory("path"):-Directory("name")
        m = re.match(r'(?:root|[Dd]irectory\("([^"]*)"\))\s*:-\s*'
                     r'(?:Perm)?[Dd]irectory\("([^"]*)"\)', line)
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
            host = os.path.join(fs_dir, full.lstrip(chr(92)).replace(chr(92), os.sep))
            os.makedirs(host, exist_ok=True)
            dirs_created += 1
            continue

        # Directory("path"):-File("destname","srcpath")
        m = re.match(r'[Dd]irectory\("([^"]*)"\)\s*:-\s*[Ff]ile\("([^"]*)",\s*"([^"]*)"\)', line)
        if m:
            dest_dir = m.group(1).replace('\\\\', chr(92))
            dest_name = _decode_hex_name(m.group(2))
            src_path = m.group(3).replace('\\\\', chr(92))

            if not dest_dir.startswith(chr(92)):
                dest_dir = chr(92) + dest_dir

            src_file = os.path.basename(src_path)
            src_full = os.path.join(win_dir, src_file)

            dest_full_dir = os.path.join(fs_dir, dest_dir.lstrip(chr(92)).replace(chr(92), os.sep))
            os.makedirs(dest_full_dir, exist_ok=True)
            dest_full = os.path.join(dest_full_dir, dest_name)

            if os.path.isfile(src_full) and not os.path.exists(dest_full):
                shutil.copy2(src_full, dest_full)
                files_placed += 1
                if attr_log is not None:
                    src_key = '\\Windows\\' + src_file
                    if src_key in attr_log:
                        placed_key = dest_dir.rstrip(chr(92)) + chr(92) + dest_name
                        attr_log[placed_key] = attr_log[src_key]

    print(f"\nDirectory structure (from {iff_source}):")
    print(f"  {dirs_created} directories created")
    print(f"  {files_placed} files placed")


# ── Registry post-processing ────────────────────────────────────────────────

def _convert_rgu_to_reg(src, dst):
    """WM5+: .rgu is UTF-16LE text. Convert to UTF-8 with normalised line endings."""
    try:
        with open(src, 'rb') as f:
            raw = f.read()
        if raw[:2] == b'\xff\xfe':
            text = raw[2:].decode('utf-16-le', errors='replace')
        else:
            text = raw.decode('utf-16-le', errors='replace')
        text = text.replace('\r\n', '\n').replace('\r', '\n')
        with open(dst, 'w', encoding='utf-8') as f:
            f.write(text)
    except Exception:
        shutil.copy2(src, dst)


def _post_process_registry(out_dir, win_dir):
    """Convert registry blobs from <out>/Windows/ into <out>/Registry/.

    WM5+        : .rgu (UTF-16 text) -> UTF-8 .reg
                  .hv  (binary hive) -> copied verbatim
    CE3 / WM2003: default.fdf (binary boot registry) -> UTF-8 .reg
    """
    rgu_files = sorted(f for f in os.listdir(win_dir)
                       if f.lower().endswith('.rgu'))
    hv_files = [f for f in os.listdir(win_dir)
                if f.lower().endswith('.hv')]
    fdf_files = []
    for cand in ("default.fdf",):
        p = os.path.join(win_dir, cand)
        if os.path.isfile(p):
            with open(p, 'rb') as f:
                head = f.read(len(CE_FDF_MAGIC))
            if head == CE_FDF_MAGIC:
                fdf_files.append(cand)

    if not (rgu_files or hv_files or fdf_files):
        return

    reg_dir = os.path.join(out_dir, "Registry")
    os.makedirs(reg_dir, exist_ok=True)
    print(f"\nRegistry files:")

    for rgu in rgu_files:
        src = os.path.join(win_dir, rgu)
        dst = os.path.join(reg_dir, os.path.splitext(rgu)[0] + '.reg')
        _convert_rgu_to_reg(src, dst)
        # Also preserve the original .rgu next to the converted .reg
        shutil.copy2(src, os.path.join(reg_dir, rgu))

    for hv in hv_files:
        shutil.copy2(os.path.join(win_dir, hv), os.path.join(reg_dir, hv))

    fdf_converted = 0
    for fn in fdf_files:
        src = os.path.join(win_dir, fn)
        with open(src, 'rb') as f:
            raw = f.read()
        # Preserve the original .fdf next to the converted .reg
        shutil.copy2(src, os.path.join(reg_dir, fn))
        records = parse_fdf_registry(raw)
        if records:
            text = fdf_to_reg_text(records)
            dst = os.path.join(reg_dir, os.path.splitext(fn)[0] + '.reg')
            with open(dst, 'w', encoding='utf-8') as f:
                f.write(text)
            fdf_converted += 1

    if rgu_files:
        print(f"  {len(rgu_files)} .reg files -> {reg_dir} (UTF-8)")
    if hv_files:
        print(f"  {len(hv_files)} .hv hive files -> {reg_dir}")
    if fdf_converted:
        print(f"  {fdf_converted} boot registry (.fdf) converted "
              f"to .reg -> {reg_dir}")


# ── Attribute map ───────────────────────────────────────────────────────────

def _write_attribute_ini(out_dir, attr_log):
    """Write the captured CE attribute map to <out>/attributes.ini.

    Files extracted to disk lose their CE attribute bits (host FS gets the
    Windows default `Archive` only). The emulator can re-apply the original
    bits by reading this file at boot.
    """
    if not attr_log:
        return
    path = os.path.join(out_dir, 'attributes.ini')
    with open(path, 'w', encoding='utf-8') as f:
        f.write("; CE filesystem attribute map.\n")
        f.write(";\n")
        f.write("; <ce_path> = <attrs_hex> <filetime_hex>\n")
        f.write(";\n")
        f.write("; bits: 0x01=RO  0x02=HIDDEN  0x04=SYSTEM  0x10=DIR\n")
        f.write(";       0x20=ARCHIVE  0x40=INROM  0x80=NORMAL  0x100=TEMPORARY\n")
        f.write(";       0x800=COMPRESSED\n")
        f.write(";       0x40000000=ROMMODULE  0x80000000=ROMSTATICREF\n")
        f.write("; filetime: 64-bit Windows FILETIME (100ns since 1601-01-01 UTC)\n")
        f.write("\n[Files]\n")
        for p in sorted(attr_log):
            attrs, ft = attr_log[p]
            f.write(f"{p} = 0x{attrs:08X} 0x{ft:016X}\n")
    print(f"  attribute map ({len(attr_log)} entries) -> {path}")


# ── rom_meta.json ───────────────────────────────────────────────────────────

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


# ── Sections/ emission ──────────────────────────────────────────────────────

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



def _emit_sections(out_dir, sections_mode, rom_meta, fmt, *,
                   b000ff_data=None, b000ff_records=None,
                   nb0_data=None, nb0_load_offset=None):
    """Write Sections/ files. `sections_mode` is 'full' or 'non-module'.

    full: B000FF -> one file per ROM section (preserved native layout);
          NB0   -> one file with the whole flat image.
    non-module: emit only the byte ranges consumers need without
          fs/ - shared-RVA module sections + the IMGFS region.
    """
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


# ── Main pipeline ───────────────────────────────────────────────────────────

def extract_image(bin_path, fs_mode='raw', sections_mode='non-module', out_dir=None):
    """Extract a Windows CE / Windows Mobile ROM image.

    fs_mode controls filesystem reconstruction:
      'raw' (default): per-module PE under <out>/fs/Windows/, bytes
                       verbatim from ROM at link-time RVAs. Every PE
                       carries an appended `.cerom` section with CE-
                       specific per-module metadata; shared-RVA /
                       split-address modules also carry their full
                       o32_rom set + shadow bytes there.
      'heuristic':     same plus synth .reloc / un-rebase / IAT
                       unbinding passes. Synth has known FPs - not for
                       production use.
      'no':            skip <out>/fs/, <out>/Registry/, and
                       <out>/attributes.ini. Output is
                       <out>/rom_meta.json + <out>/Sections/ only.

    sections_mode controls the Sections/ folder:
      'non-module' (default): kernel-VA byte ranges not covered by any
                                    module's PE (bootloader, ROMHDR /
                                    TOC / FILESentry / COPYentry /
                                    ROMPID kernel structures, IMGFS
                                    region, padding).
      'full':                       B000FF: one file per ROM section
                                    (native layout). NB0: one file with
                                    the entire flat image.

    out_dir defaults to <dir-of-bin>/<basename-without-extension>/.
    """
    skip_fs = (fs_mode == 'no')
    print(f"Reading {bin_path}...")
    with open(bin_path, 'rb') as f:
        data = f.read()
    print(f"  {len(data)} bytes ({len(data) / 1024 / 1024:.1f} MB)")

    if out_dir is None:
        base_name = os.path.splitext(os.path.basename(bin_path))[0]
        out_dir = os.path.join(os.path.dirname(os.path.abspath(bin_path)), base_name)
    else:
        out_dir = os.path.abspath(out_dir)

    if os.path.exists(out_dir):
        print(f"Cleaning {out_dir}")
        shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    is_b000ff = data[:7] == b'B000FF\n'
    attr_log = {}  # CE-style path -> (attrs, filetime); written at the end
    rom_meta = _new_rom_meta()

    if is_b000ff:
        # B000FF container (WM2003 / WM5)
        print("\nFormat: B000FF (section container)")
        flat, base_va, records = parse_b000ff(data)
        if flat is None:
            print("ERROR: Failed to parse B000FF container")
            return False

        print("\nExtracting XIP regions...")
        extract_xip_regions(flat, base_va, out_dir, attr_log=attr_log,
                            fs_mode=fs_mode, rom_meta=rom_meta)

        print(f"\nWriting Sections/ ({sections_mode})...")
        _emit_sections(out_dir, sections_mode, rom_meta, fmt='b000ff',
                       b000ff_data=data, b000ff_records=records)
    else:
        # NB0 flat image (WM6+). Verify ARM branch at offset 0.
        sig = u32(data, 0)
        if sig & 0xEA000000 != 0xEA000000:
            print(f"WARNING: Not a recognised format (sig=0x{sig:08X})")

        print("\nFormat: NB0 flat image")

        has_imgfs = find_imgfs_base(data) != -1

        print("\nExtracting XIP regions...")
        extract_xip_regions(data, 0, out_dir, attr_log=attr_log,
                            fs_mode=fs_mode, rom_meta=rom_meta)

        if has_imgfs:
            print("\nExtracting IMGFS filesystem...")
            extract_imgfs(data, out_dir, attr_log=attr_log,
                          fs_mode=fs_mode, rom_meta=rom_meta)

        load_offset = rom_meta.get('_load_offset')
        if load_offset is not None:
            print(f"\nWriting Sections/ ({sections_mode})...")
            _emit_sections(out_dir, sections_mode, rom_meta, fmt='nb0',
                           nb0_data=data, nb0_load_offset=load_offset)

    fs_dir = os.path.join(out_dir, "fs")
    win_dir = os.path.join(fs_dir, "Windows")
    if not skip_fs and os.path.isdir(win_dir):
        _post_process_fs(fs_dir, win_dir, attr_log=attr_log)
        _post_process_registry(out_dir, win_dir)

    if not skip_fs:
        _write_attribute_ini(out_dir, attr_log)
    _write_rom_meta(out_dir, rom_meta)

    print(f"\nDone -> {out_dir}")
    return True
