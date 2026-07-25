"""Top-level extraction pipeline:
    1. Read ROM image (.BIN B000FF, .nb0 flat)
    2. Walk XIP regions -> emit reconstructed PE files into <out>/Windows/
    3. (NB0 only) Walk IMGFS filesystem -> emit files / modules
    4. Post-process: rebuild directory tree from initflashfiles.dat / initobj.dat
    5. Post-process: convert registry blobs (.rgu / .hv / default.fdf) into <out>/Registry/
    6. Emit rom_meta.json with ROMHDR fields, module/file inventory, romhdr_va
"""

import os
import re
import shutil

from .util import u32
from .b000ff import parse_b000ff
from .ce1 import is_ce1_rom, extract_ce1
from .xip import extract_xip_regions, probe_cpu_types
from .imgfs import IMGFS_UUID, find_imgfs_base, extract_imgfs
from .machine import resolve_machine
from .registry import CE_FDF_MAGIC, parse_fdf_registry, fdf_to_reg_text
from .rom_meta import _new_rom_meta, _write_rom_meta
from .sections import emit_sections


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


# ── Main pipeline ───────────────────────────────────────────────────────────

def extract_image(bin_path, fs_mode='raw', sections_mode='non-module', out_dir=None,
                  machine_override=None):
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
      'no':                         skip the Sections/ folder entirely.

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

    is_b000ff = data[:7] == b'B000FF\n'
    is_ce1 = is_ce1_rom(data)

    flat, base_va, records = None, None, None
    if is_b000ff:
        flat, base_va, records = parse_b000ff(data)
        if flat is None:
            print("ERROR: Failed to parse B000FF container")
            return False

    # Every region's machine resolves before out_dir is touched: an image
    # that needs --machine must not cost the caller a previous extraction.
    if not is_ce1:
        for cpu in probe_cpu_types(*((flat, base_va) if is_b000ff else (data, 0))):
            resolve_machine(cpu, machine_override)

    if os.path.exists(out_dir):
        print(f"Cleaning {out_dir}")
        shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    attr_log = {}  # CE-style path -> (attrs, filetime); written at the end
    rom_meta = _new_rom_meta()

    if is_b000ff:
        # B000FF container (WM2003 / WM5)
        print("\nFormat: B000FF (section container)")
        print("\nExtracting XIP regions...")
        extract_xip_regions(flat, base_va, out_dir, attr_log=attr_log,
                            fs_mode=fs_mode, rom_meta=rom_meta,
                            machine_override=machine_override)

        print(f"\nWriting Sections/ ({sections_mode})...")
        emit_sections(out_dir, sections_mode, rom_meta, fmt='b000ff',
                       b000ff_data=data, b000ff_records=records)
    elif is_ce1_rom(data):
        print("\nFormat: Windows CE 1.0 XIP")
        print("\nExtracting XIP regions...")
        extract_ce1(data, out_dir, attr_log=attr_log, fs_mode=fs_mode,
                    rom_meta=rom_meta)
        load_offset = rom_meta.get('_load_offset')
        if load_offset is not None:
            print(f"\nWriting Sections/ ({sections_mode})...")
            emit_sections(out_dir, sections_mode, rom_meta, fmt='nb0',
                           nb0_data=data, nb0_load_offset=load_offset)
    else:
        # NB0 flat image (WM6+). Verify ARM branch at offset 0.
        sig = u32(data, 0)
        if sig & 0xEA000000 != 0xEA000000:
            print(f"WARNING: Not a recognised format (sig=0x{sig:08X})")

        print("\nFormat: NB0 flat image")

        has_imgfs = find_imgfs_base(data) != -1

        print("\nExtracting XIP regions...")
        extract_xip_regions(data, 0, out_dir, attr_log=attr_log,
                            fs_mode=fs_mode, rom_meta=rom_meta,
                            machine_override=machine_override)

        if has_imgfs:
            print("\nExtracting IMGFS filesystem...")
            imgfs_machine = resolve_machine(rom_meta.get('_cpu_type', 0),
                                            machine_override)
            extract_imgfs(data, out_dir, imgfs_machine, attr_log=attr_log,
                          fs_mode=fs_mode, rom_meta=rom_meta)

        load_offset = rom_meta.get('_load_offset')
        if load_offset is not None:
            print(f"\nWriting Sections/ ({sections_mode})...")
            emit_sections(out_dir, sections_mode, rom_meta, fmt='nb0',
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
