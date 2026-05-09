#!/usr/bin/env python3
"""CLI entry point for the winmob_extract package."""

import os
import sys

from winmob_extract import extract_image


HELP = """\
Usage: python extract_wince_rom.py [--fs=MODE] [--sections=MODE] <image.BIN|.nb0> [...]
   or: place .BIN/.nb0 files next to this script

--fs=MODE controls filesystem reconstruction (default: --fs=raw):

  raw        Reconstruct each module as a PE under <out>/fs/Windows/.
             Bytes verbatim from ROM at original link-time RVAs. Most
             modules emit strict-conforming PEs. Modules with shared-RVA
             sections (CE allows two o32 records at the same rva - a
             writable RAM-mapped section and a read-only ROM-mapped
             section overlaid at the same link-time slot, never live
             simultaneously, but PE format requires distinct
             VirtualAddresses) are routed to <out>/fs__bad_overlaps/
             with original RVAs preserved. PE there is technically
             PE-spec invalid (Windows PE loader rejects); IDA, Ghidra
             and objdump parse it. Section runtime layout (realaddr)
             is in rom_meta.json's modules[i].sections[].

  heuristic  raw + synth .reloc + un-rebase DLLs to ImageBase=
             0x10000000 + IAT bound -> unbound. The .reloc synth has
             structural false positives (ARM literal pools, resource
             sentinels, coincidental in-range constants collide with
             real pointers) and can corrupt embedded constants when
             consumers re-relocate. Not recommended for production.

  no         Skip filesystem reconstruction. Output is rom_meta.json
             + Sections/ only - no fs/, no fs__bad_overlaps/, no
             Registry/, no attributes.ini.

--sections=MODE controls the Sections/ folder (default:
                                              --sections=only-overlapping):

  only-overlapping  Emit only the byte ranges consumers need without
                    fs/ - shared-RVA module sections + the IMGFS region
                    (when present). Smallest output. Suitable for
                    consumers driving runtime synthesis from rom_meta
                    + Sections/.

  full              B000FF: one file per ROM section (native layout).
                    NB0: one file with the entire flat kernel-VA image.
                    Suitable for full reverse engineering or recovering
                    bootloaders / boot images that have no ECEC marker.
"""


def main():
    args = sys.argv[1:]
    fs_mode = 'raw'
    sections_mode = 'only-overlapping'
    filtered = []
    for a in args:
        if a.startswith('--fs='):
            v = a.split('=', 1)[1]
            if v not in ('no', 'raw', 'heuristic'):
                print(f"ERROR: invalid --fs value: {v!r}. Use no, raw, or heuristic.")
                return 1
            fs_mode = v
        elif a.startswith('--sections='):
            v = a.split('=', 1)[1]
            if v not in ('full', 'only-overlapping'):
                print(f"ERROR: invalid --sections value: {v!r}. Use full or only-overlapping.")
                return 1
            sections_mode = v
        else:
            filtered.append(a)
    args = filtered
    if any(a in args for a in ('-h', '--help')):
        print(HELP); return 0

    if args:
        paths = args
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        paths = sorted(
            os.path.join(here, f)
            for f in os.listdir(here)
            if f.upper().endswith(('.BIN', '.NB0')) and os.path.isfile(os.path.join(here, f))
        )
        if not paths:
            print(HELP); sys.exit(1)

    if fs_mode == 'heuristic':
        print("WARNING: --fs=heuristic enabled. Synth .reloc + un-rebase + IAT")
        print("         unbinding produce structural false positives on some")
        print("         binaries. Not recommended for production input.")

    if fs_mode == 'no' and sections_mode == 'only-overlapping':
        print("WARNING: --fs=no with --sections=only-overlapping skips most of")
        print("         the filesystem. Sections/ will only carry shared-RVA")
        print("         module bytes plus the IMGFS region (if present); fs/")
        print("         is not produced. Most non-kernel modules and files")
        print("         will be unreadable from this output. Use")
        print("         --sections=full or --fs=raw if that's not intended.")

    for p in paths:
        if not os.path.isfile(p):
            print(f"ERROR: Not found: {p}")
            continue
        print("=" * 60)
        extract_image(p, fs_mode=fs_mode, sections_mode=sections_mode)
        print()


if __name__ == '__main__':
    main()
