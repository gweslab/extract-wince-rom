# extract-wince-rom

Extracts Windows CE ROM images (.BIN, .nb0) into usable files: reconstructed PE executables, media, registry, and directory structure.

Targets Microsoft Device Emulator images and OEM dumps (Pocket PC 2000 / WM2003SE / WM5 / WM6 / WM6.5 / WM6.5.3).

> [!WARNING]
> **`.reloc` synthesis is inherently approximate.** The ROM builder strips the original base-relocation directory (XIP modules don't need it at load time), so there is no ground truth — entries are reconstructed by scanning section bytes for 4-byte values that fall within the module's image range. ARM instruction encodings, resource sentinels, and coincidental in-range values all collide with real pointers, and every `.reloc` bug shipped so far has come from this pass. Expect more.
>
> Other stages (B000FF/NB0 parsing, XIP PE reconstruction, LZX/XPRESS decompression, IMGFS walk, IAT repair, RGU→REG conversion) are documented format parsing and should be correct in principle, but **have not been independently verified** against a reference implementation. Treat all output as best-effort.

## Features

- **B000FF** (sectioned container) and **NB0** (flat binary) ROM formats
- **XIP modules** with LZX (CE 4+) and CE3 BIN (Pocket PC 2000) decompression, and full PE32 reconstruction from `e32_rom`/`o32_rom` headers
- **IMGFS filesystem** extraction with Flash Translation Layer page mapping and XPRESS decompression
- **Relocation fixup** for XIP PEs: patches split-address references (`o32_realaddr`) and generates `.reloc` sections covering all absolute references within each module's image range
- **Import table repair**: overwrites ROM-baked IAT entries with original ILT ordinal/name hints
- **Directory structure** from `initflashfiles.dat` (WM5+) or `initobj.dat` (CE3 / WM2003)
- **Registry** extraction: `.rgu` → UTF-8 `.reg` (WM5+) and `default.fdf` binary boot registry → `.reg` (CE3 / WM2003)

## Usage

```
python extract_wince_rom.py <image.BIN|.nb0> [image2.BIN ...]
```

Or place `.BIN`/`.nb0` files next to the script and run without arguments.

Output goes to a directory named after the image (e.g. `WM5_PPC_USA/`).

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
