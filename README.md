# extract-wince-rom

Extracts Windows CE ROM images (.BIN, .nb0) into usable files: PE executables, media, registry, directory structure, and a `rom_meta.json` describing the ROMHDR / TOC / FILES / ROMPID metadata.

Targets Microsoft Device Emulator images and OEM dumps from Pocket PC 2000 through Windows Phone 7, including Zune OS (CE 5.0 / CE 6.0) firmware.

> [!WARNING]
> **`.reloc` synthesis is inherently approximate** and is **off by default** as of this version. It runs only when `--heuristic-reconstruction` is passed. The ROM builder strips the original base-relocation directory, so there is no ground truth — synth entries are reconstructed by scanning section bytes for 4-byte values that fall within the module's image range. ARM instruction encodings, resource sentinels, and coincidental in-range values all collide with real pointers; expect false positives that corrupt embedded constants when consumers re-relocate the PE. Default (raw) mode skips synth entirely and sets `IMAGE_FILE_RELOCS_STRIPPED` so loaders fail loud rather than apply a faulty table.
>
> Other stages (B000FF/NB0 parsing, XIP PE reconstruction, LZX/XPRESS decompression, IMGFS walk, RGU→REG conversion) are documented format parsing and should be correct in principle, but **have not been independently verified** against a reference implementation. Treat all output as best-effort.

## Features

- **B000FF** (sectioned container) and **NB0** (flat binary) ROM formats
- **XIP modules** with LZX (CE 4+) and CE3 BIN (Pocket PC 2000) decompression, and PE32 reconstruction from `e32_rom`/`o32_rom` headers
- **IMGFS filesystem** extraction with Flash Translation Layer page mapping and XPRESS decompression
- **Section overlap resolution** for ROMs whose o32 records share an RVA (writable RAM section + read-only XIP section overlaid)
- **Relocation fixup** for XIP PEs (heuristic mode only): patches split-address references (`o32_realaddr`) and synthesizes `.reloc` sections by scanning for absolute references
- **Import table repair** (heuristic mode only): overwrites ROM-baked IAT entries with original ILT ordinal/name hints
- **Directory structure** from `initflashfiles.dat` (WM5+) or `initobj.dat` (CE3 / WM2003)
- **Registry** extraction: `.rgu` → UTF-8 `.reg` (WM5+), `.hv` preserved verbatim (WM5+), and `default.fdf` binary boot registry → `.reg` (CE3 / WM2003)
- **`rom_meta.json`** with ROMHDR fields, ROMPID extension chain, module/file inventory, and `romhdr_va` (the value at `physfirst+0x44` per `romldr.h`'s `ROM_TOC_POINTER_OFFSET`, populated across CE3..CE7)

## Modes

**Raw (default).** PEs come out byte-faithful to ROM: `ImageBase=vbase`, IAT bound as ROM stored it, no `.reloc` synthesis, `IMAGE_FILE_RELOCS_STRIPPED` set when the ROM has no preserved reloc table. Zero byte modification beyond what's required to produce a valid PE container.

**Heuristic** (`--heuristic-reconstruction`). Adds `.reloc` synthesis, un-rebases DLLs to canonical `ImageBase=0x10000000`, and converts IAT from bound to unbound. The synth pass has structural false positives that can corrupt embedded constants. Not recommended for production input.

## Usage

```
python extract_wince_rom.py [--heuristic-reconstruction] <image.BIN|.nb0> [...]
```

Or place `.BIN`/`.nb0` files next to the script and run without arguments.

Output goes to a directory named after the image (e.g. `WM5_PPC_USA/`):

```
<image-name>/
  fs/                  reconstructed CE filesystem
    Windows/           PEs and verbatim non-module files
    Program Files/     placed per initflashfiles.dat / initobj.dat
    My Documents/
    ...
  Sections/            (B000FF only) raw section dumps from the container
  Registry/            .rgu / .hv / default.fdf and converted .reg files
  attributes.ini       CE filesystem attribute bits + FILETIME per path
  rom_meta.json        ROMHDR / TOC / FILES / ROMPID metadata
```

## Tested images

| Image(s) | OS | Arch | Device | Format |
|----------|----|------|--------|--------|
| `IPAQROM177.nb0` | Pocket PC 2000 | ARM | Compaq iPAQ 3600/3650 | NB0 |
| `ASUS_A6X6_WM61.nb0` | Windows Mobile 6.1 | ARM | Asus Mypal A6x6 | NB0 |
| `WM2003SE.bin` | Windows Mobile 2003 SE | ARM | Device Emulator | B000FF |
| `WM5_PPC_USA.BIN`, `510SP.bin` | Windows Mobile 5 (Pocket PC and Smartphone editions) | ARM | Device Emulator | B000FF |
| `WM6_PPC_USA_GSM_VR.BIN` | Windows Mobile 6 | ARM | Device Emulator | NB0 |
| `WM65_PPC_USA_GSM_VR.BIN` | Windows Mobile 6.5 | ARM | Device Emulator | NB0 |
| `WM653_PPC_USA_GSM_VR.BIN` | Windows Mobile 6.5.3 | ARM | Device Emulator | NB0 |
| `700WP.bin` | Windows Phone 7 | x86 | Device Emulator | B000FF |
| `Eboot.bin`, `nk.bin`, `recovery.bin` | Zune OS (CE 5.0) | ARM | Keel (Zune 30, 1st gen 2006) | B000FF |
| `Eboot.bin`, `nk.bin`, `recovery.bin` | Zune OS (CE 5.0) | ARM | Draco (Zune 80 / 120, 2nd gen HDD, 2007/2008) | B000FF |
| `Eboot.bin`, `nk.bin`, `recovery.bin` | Zune OS (CE 5.0) | ARM | Scorpius (Zune 4 / 8 / 16, 2nd gen flash, 2007/2008) | B000FF |
| `Eboot.bin`, `nk.bin`, `recovery.bin` | Zune OS (CE 6.0) | ARM | Pavo (Zune HD, 3rd gen 2009, Tegra) | B000FF |

## Requirements

- Python 3.8+
- No pip dependencies

```
git clone --recursive <repo-url>
```

## Credits

- [KodaSec/wince-decompr](https://github.com/KodaSec/wince-decompr) -- LZX decompression for CE ROM sections
- [coderforlife/ms-compress](https://github.com/coderforlife/ms-compress) -- reference implementation used to verify XPRESS decompression correctness
