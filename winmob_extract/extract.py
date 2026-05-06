"""Top-level extraction pipeline:
    1. Read ROM image (.BIN B000FF, .nb0 flat)
    2. Walk XIP regions -> emit reconstructed PE files into <out>/Windows/
    3. (NB0 only) Walk IMGFS filesystem -> emit files / modules
    4. Post-process: rebuild directory tree from initflashfiles.dat / initobj.dat
    5. Post-process: convert registry blobs (.rgu / .hv / default.fdf) into <out>/Registry/
"""

import os
import re
import shutil

from .util import u32
from .b000ff import parse_b000ff
from .xip import extract_xip_regions
from .imgfs import IMGFS_UUID, IMGFS_DIRENT_SIZE, find_imgfs_base, extract_imgfs
from .registry import (WM2003_REG_MAGIC, parse_wm2003_fdf,
                       wm2003_fdf_to_reg_text)


# ── Directory structure (initflashfiles.dat / initobj.dat) ──────────────────

def _decode_hex_name(s):
    """Decode \\x00XX hex sequences to characters."""
    return re.sub(r'\\x([0-9A-Fa-f]{4})',
                  lambda m: chr(int(m.group(1), 16)), s)


def _post_process_fs(out_dir, win_dir):
    """Rebuild directory tree from initflashfiles.dat (WM5+) or
    initobj.dat (WM2003). Same syntax in both."""
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
            host = os.path.join(out_dir, full.lstrip(chr(92)).replace(chr(92), os.sep))
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

            dest_full_dir = os.path.join(out_dir, dest_dir.lstrip(chr(92)).replace(chr(92), os.sep))
            os.makedirs(dest_full_dir, exist_ok=True)
            dest_full = os.path.join(dest_full_dir, dest_name)

            if os.path.isfile(src_full) and not os.path.exists(dest_full):
                shutil.copy2(src_full, dest_full)
                files_placed += 1

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

    WM5+ : .rgu (UTF-16 text) -> UTF-8 .reg
           .hv  (binary hive) -> copied verbatim
    WM2003: default.fdf (binary boot registry) -> UTF-8 .reg
    """
    rgu_files = sorted(f for f in os.listdir(win_dir)
                       if f.lower().endswith('.rgu'))
    hv_files = [f for f in os.listdir(win_dir)
                if f.lower().endswith('.hv')]
    wm2003_fdf = []
    for cand in ("default.fdf",):
        p = os.path.join(win_dir, cand)
        if os.path.isfile(p):
            with open(p, 'rb') as f:
                head = f.read(len(WM2003_REG_MAGIC))
            if head == WM2003_REG_MAGIC:
                wm2003_fdf.append(cand)

    if not (rgu_files or hv_files or wm2003_fdf):
        return

    reg_dir = os.path.join(out_dir, "Registry")
    os.makedirs(reg_dir, exist_ok=True)
    print(f"\nRegistry files:")

    for rgu in rgu_files:
        src = os.path.join(win_dir, rgu)
        dst = os.path.join(reg_dir, os.path.splitext(rgu)[0] + '.reg')
        _convert_rgu_to_reg(src, dst)

    for hv in hv_files:
        shutil.copy2(os.path.join(win_dir, hv), os.path.join(reg_dir, hv))

    wm2003_converted = 0
    for fn in wm2003_fdf:
        src = os.path.join(win_dir, fn)
        with open(src, 'rb') as f:
            raw = f.read()
        records = parse_wm2003_fdf(raw)
        if records:
            text = wm2003_fdf_to_reg_text(records)
            dst = os.path.join(reg_dir, os.path.splitext(fn)[0] + '.reg')
            with open(dst, 'w', encoding='utf-8') as f:
                f.write(text)
            wm2003_converted += 1
        else:
            shutil.copy2(src, os.path.join(reg_dir, fn))

    if rgu_files:
        print(f"  {len(rgu_files)} .reg files -> {reg_dir} (UTF-8)")
    if hv_files:
        print(f"  {len(hv_files)} .hv hive files -> {reg_dir}")
    if wm2003_converted:
        print(f"  {wm2003_converted} WM2003 boot registry converted "
              f"to .reg -> {reg_dir}")


# ── Main pipeline ───────────────────────────────────────────────────────────

def extract_image(bin_path):
    """Extract a Windows CE / Windows Mobile ROM image."""
    print(f"Reading {bin_path}...")
    with open(bin_path, 'rb') as f:
        data = f.read()
    print(f"  {len(data)} bytes ({len(data) / 1024 / 1024:.1f} MB)")

    base_name = os.path.splitext(os.path.basename(bin_path))[0]
    out_dir = os.path.join(os.path.dirname(os.path.abspath(bin_path)), base_name)

    if os.path.exists(out_dir):
        print(f"Cleaning {out_dir}")
        shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)

    is_b000ff = data[:7] == b'B000FF\n'

    if is_b000ff:
        # B000FF container (WM2003, WM5)
        print("\nFormat: B000FF (section container)")
        flat, base_va = parse_b000ff(data)
        if flat is None:
            print("ERROR: Failed to parse B000FF container")
            return False

        print("\nExtracting XIP regions...")
        extract_xip_regions(flat, base_va, out_dir)
    else:
        # NB0 flat image (WM6+). Verify ARM branch at offset 0.
        sig = u32(data, 0)
        if sig & 0xEA000000 != 0xEA000000:
            print(f"WARNING: Not a recognised format (sig=0x{sig:08X})")

        print("\nFormat: NB0 flat image")

        has_imgfs = find_imgfs_base(data) != -1

        print("\nExtracting XIP regions...")
        extract_xip_regions(data, 0, out_dir)

        if has_imgfs:
            print("\nExtracting IMGFS filesystem...")
            extract_imgfs(data, out_dir)

    win_dir = os.path.join(out_dir, "Windows")
    if os.path.isdir(win_dir):
        _post_process_fs(out_dir, win_dir)
        _post_process_registry(out_dir, win_dir)

    print(f"\nDone -> {out_dir}")
    return True
