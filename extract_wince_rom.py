#!/usr/bin/env python3
"""CLI entry point for the winmob_extract package."""

import os
import sys

from winmob_extract import extract_image


HELP = """\
Usage: python extract_wince_rom.py [--heuristic-reconstruction] <image.BIN|.nb0> [...]
   or: place .BIN/.nb0 files next to this script

By default the extractor produces ROM-faithful PEs (bytes verbatim from
ROM, ImageBase=vbase, IAT bound as ROM has it, no .reloc synthesis,
RELOCS_STRIPPED set when the ROM did not preserve a reloc table). Zero
byte modification, zero corruption.

--heuristic-reconstruction enables the legacy passes: synth .reloc,
un-rebase to canonical ImageBase=0x10000000, IAT converted from bound
to unbound. The synth has structural false positives that corrupt
embedded constants. NOT recommended; kept for experimentation.
"""


def main():
    args = sys.argv[1:]
    heuristic = False
    if '--heuristic-reconstruction' in args:
        heuristic = True
        args = [a for a in args if a != '--heuristic-reconstruction']
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

    if heuristic:
        print("WARNING: --heuristic-reconstruction is enabled. Synth .reloc and")
        print("         un-rebase are known to produce false positives on some")
        print("         binaries. Not recommended for production input.")

    for p in paths:
        if not os.path.isfile(p):
            print(f"ERROR: Not found: {p}")
            continue
        print("=" * 60)
        extract_image(p, heuristic=heuristic)
        print()


if __name__ == '__main__':
    main()
