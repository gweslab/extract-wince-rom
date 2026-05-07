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
import sys

from winmob_extract.extract import _post_process_fs, _post_process_registry


def process_sysgen(sysgen_dir, out_dir):
    win_dir = os.path.join(sysgen_dir, "Windows")
    if not os.path.isdir(win_dir):
        win_dir = sysgen_dir

    print(f"Source: {win_dir}")
    print(f"Output: {out_dir}")
    os.makedirs(out_dir, exist_ok=True)

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
