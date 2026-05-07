#!/usr/bin/env python3
"""Apply CE post-processing to a sysgen output tree.

Takes a directory produced by Platform Builder sysgen (the same
`initobj.dat` / `initflashfiles.dat` + `default.fdf` / `.rgu` / `.hv`
files that a ROM image carries, just unpacked) and produces:

  - a restructured filesystem tree per the manifest, mirroring the layout
    the runtime ROM filesystem would expose
  - `<out>/Registry/` with `.reg` text converted from the boot registry

Usage:
    python postprocess_sysgen.py <sysgen_dir> [output_dir]

Default output_dir: `<sysgen_dir>_processed`.
"""

import os
import shutil
import sys

from winmob_extract.extract import _post_process_fs, _post_process_registry


def process_sysgen(sysgen_dir, out_dir):
    src_dir = os.path.join(sysgen_dir, "Windows")
    if not os.path.isdir(src_dir):
        src_dir = sysgen_dir

    win_dir = os.path.join(out_dir, "Windows")
    print(f"Source: {src_dir}")
    print(f"Output: {out_dir}")
    os.makedirs(win_dir, exist_ok=True)

    # Mirror the sysgen tree into <out>/Windows/ so the output mirrors a
    # ROM-extraction layout (canonical \Windows\ + placement copies on top).
    copied = 0
    for root, dirs, files in os.walk(src_dir):
        rel = os.path.relpath(root, src_dir)
        dst_root = win_dir if rel == '.' else os.path.join(win_dir, rel)
        os.makedirs(dst_root, exist_ok=True)
        for f in files:
            shutil.copy2(os.path.join(root, f), os.path.join(dst_root, f))
            copied += 1
    print(f"  {copied} files mirrored -> {win_dir}")

    _post_process_fs(out_dir, win_dir)
    _post_process_registry(out_dir, win_dir)

    print(f"\nDone -> {out_dir}")


def main():
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help'):
        print(__doc__.strip())
        return 1
    sysgen_dir = os.path.abspath(args[0])
    if not os.path.isdir(sysgen_dir):
        print(f"ERROR: not a directory: {sysgen_dir}")
        return 1
    out_dir = os.path.abspath(args[1]) if len(args) > 1 else sysgen_dir + "_processed"
    process_sysgen(sysgen_dir, out_dir)
    return 0


if __name__ == '__main__':
    sys.exit(main())
