# extract-wince-rom

Extracts Windows CE ROM images (.BIN, .nb0) into usable files: reconstructed PE executables, media, registry, and directory structure.

Targets Microsoft Device Emulator images and OEM dumps (WM5 / WM6 / WM6.5 / WM6.5.3).

> [!WARNING]
> **`.reloc` synthesis is inherently approximate.** The ROM builder strips the original base-relocation directory (XIP modules don't need it at load time), so there is no ground truth — entries are reconstructed by scanning section bytes for 4-byte values that fall within the module's image range. ARM instruction encodings, resource sentinels, and coincidental in-range values all collide with real pointers, and every `.reloc` bug shipped so far has come from this pass. Expect more.
>
> Other stages (B000FF/NB0 parsing, XIP PE reconstruction, LZX/XPRESS decompression, IMGFS walk, IAT repair, RGU→REG conversion) are documented format parsing and should be correct in principle, but **have not been independently verified** against a reference implementation. Treat all output as best-effort.

## Features

- **B000FF** (sectioned container) and **NB0** (flat binary) ROM formats
- **XIP modules** with LZX decompression and full PE32 reconstruction from `e32_rom`/`o32_rom` headers
- **IMGFS filesystem** extraction with Flash Translation Layer page mapping and XPRESS decompression
- **Relocation fixup** for XIP PEs: patches split-address references (`o32_realaddr`) and generates `.reloc` sections covering all absolute references within each module's image range
- **Import table repair**: overwrites ROM-baked IAT entries with original ILT ordinal/name hints
- **Directory structure** from `initflashfiles.dat`
- **Registry** extraction (`.rgu` to UTF-8 `.reg` conversion)

## Usage

```
python extract_wince_rom.py <image.BIN|.nb0> [image2.BIN ...]
```

Or place `.BIN`/`.nb0` files next to the script and run without arguments.

Output goes to a directory named after the image (e.g. `WM5_PPC_USA/`).

## Tested images

| Image | Format |
|-------|--------|
| `WM5_PPC_USA.BIN` | B000FF |
| `WM6_PPC_USA_GSM_VR.BIN` | NB0 |
| `WM65_PPC_USA_GSM_VR.BIN` | NB0 |
| `WM653_PPC_USA_GSM_VR.BIN` | NB0 |
| `ASUS_A6X6_WM61.nb0` (OEM!) | NB0 |

## Requirements

- Python 3.8+
- No pip dependencies

```
git clone --recursive <repo-url>
```

## Credits

- [KodaSec/wince-decompr](https://github.com/KodaSec/wince-decompr) -- LZX decompression for CE ROM sections
- [coderforlife/ms-compress](https://github.com/coderforlife/ms-compress) -- reference implementation used to verify XPRESS decompression correctness
