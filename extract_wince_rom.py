#!/usr/bin/env python3
"""CLI entry point for the winmob_extract package."""

import os
import sys

from winmob_extract import extract_image


HELP = """\
Usage: python extract_wince_rom.py [OPTIONS] <image.BIN|.nb0>

Exactly one input file (relative or absolute path).

-o PATH
--output-dir=PATH
            Output directory. Default: <dir-of-input>/<basename>/
            e.g. C:\\data\\img.bin -> C:\\data\\img\\

--fs=MODE controls filesystem reconstruction (default: --fs=raw):

  raw        Each module emits a PE-spec valid PE under
             <out>/fs/Windows/<name>. Bytes verbatim from ROM at
             original link-time RVAs. Every PE has an appended
             `.cerom` section carrying the per-module TOCentry block
             (e32_offset, o32_offset, name_offset, load_va, file_size,
             attributes, filetime, e32_vsize). For modules with
             shared-RVA collisions or split-address sections, .cerom
             additionally carries the original o32_rom records and
             shadow bytes for the second record of any shared-RVA
             pair. IDA / Ghidra / objdump / the Windows PE loader
             don't know about .cerom and ignore it.

  heuristic  raw + synth .reloc + un-rebase DLLs to ImageBase=
             0x10000000 + IAT bound -> unbound. The .reloc synth has
             structural false positives (ARM literal pools, resource
             sentinels, coincidental in-range constants collide with
             real pointers) and can corrupt embedded constants when
             consumers re-relocate. Not recommended for production.

  no         Skip filesystem reconstruction. Output is rom_meta.json
             + Sections/ only - no fs/, no Registry/, no
             attributes.ini.

--sections=MODE controls the Sections/ folder (default:
                                              --sections=non-module):

  non-module  Emit kernel-VA byte ranges that aren't covered by
                    any module's PE - bootloader, ROMHDR / TOC /
                    FILESentry / COPYentry / ROMPID kernel structures,
                    the IMGFS region (when present), strings, padding.
                    Per-module bytes are already in fs/Windows/<name>'s
                    PE; this folder fills in everything else.

  full              B000FF: one file per ROM section (native layout).
                    NB0: one file with the entire flat kernel-VA image.
                    Suitable for full reverse engineering or recovering
                    bootloaders / boot images that have no ECEC marker.
"""


def main():
    args = sys.argv[1:]
    fs_mode = 'raw'
    sections_mode = 'non-module'
    out_dir = None
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ('-h', '--help'):
            print(HELP); return 0
        elif a.startswith('--fs='):
            v = a.split('=', 1)[1]
            if v not in ('no', 'raw', 'heuristic'):
                print(f"ERROR: invalid --fs value: {v!r}. Use no, raw, or heuristic.")
                return 1
            fs_mode = v
        elif a.startswith('--sections='):
            v = a.split('=', 1)[1]
            if v not in ('full', 'non-module'):
                print(f"ERROR: invalid --sections value: {v!r}. Use full or non-module.")
                return 1
            sections_mode = v
        elif a.startswith('--output-dir='):
            out_dir = a.split('=', 1)[1]
        elif a in ('-o', '--output-dir'):
            i += 1
            if i >= len(args):
                print(f"ERROR: {a} requires a path argument")
                return 1
            out_dir = args[i]
        else:
            positional.append(a)
        i += 1

    if len(positional) != 1:
        print(HELP)
        if len(positional) > 1:
            print(f"\nERROR: expected exactly one input file, got {len(positional)}")
        return 1

    bin_path = positional[0]
    if not os.path.isfile(bin_path):
        print(f"ERROR: Not found: {bin_path}")
        return 1

    if fs_mode == 'heuristic':
        print("WARNING: --fs=heuristic enabled. Synth .reloc + un-rebase + IAT")
        print("         unbinding produce structural false positives on some")
        print("         binaries. Not recommended for production input.")

    if fs_mode == 'no' and sections_mode == 'non-module':
        print("WARNING: --fs=no with --sections=non-module skips most of")
        print("         the ROM bytes. fs/ is not produced (no per-module PEs)")
        print("         and Sections/ only carries non-module byte ranges (the")
        print("         complement of module dataptr ranges). All module bytes")
        print("         and metadata are missing. Use --sections=full or")
        print("         --fs=raw if that's not intended.")

    extract_image(bin_path, fs_mode=fs_mode, sections_mode=sections_mode,
                  out_dir=out_dir)


if __name__ == '__main__':
    main()
