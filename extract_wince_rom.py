#!/usr/bin/env python3
"""CLI entry point for the winmob_extract package."""

import os
import sys

from winmob_extract import extract_image


def main():
    if len(sys.argv) > 1:
        paths = sys.argv[1:]
    else:
        # Auto-detect .BIN and .nb0 files in current directory
        here = os.path.dirname(os.path.abspath(__file__))
        paths = sorted(
            os.path.join(here, f)
            for f in os.listdir(here)
            if f.upper().endswith(('.BIN', '.NB0')) and os.path.isfile(os.path.join(here, f))
        )
        if not paths:
            print("Usage: python extract_wince_rom.py <image.BIN|.nb0> [...]")
            print("   or: place .BIN/.nb0 files next to this script")
            sys.exit(1)

    for p in paths:
        if not os.path.isfile(p):
            print(f"ERROR: Not found: {p}")
            continue
        print("=" * 60)
        extract_image(p)
        print()


if __name__ == '__main__':
    main()
