# extract-wince-rom

Decomposes Windows CE ROM images (.BIN, .nb0) into smallest chunks: PE executables, media, registry, directory structure, and a `rom_meta.json` describing the ROMHDR / TOC / FILES / ROMPID metadata.

Targets Microsoft Device Emulator images and OEM dumps from Pocket PC 2000 through Windows Phone 7, including Zune OS (CE 5.0 / CE 6.0) firmware.

> [!WARNING]
> **`.reloc` synthesis is inherently approximate** and is **off by default**. It runs only under `--fs=heuristic`. The ROM builder strips the original base-relocation directory, so there is no ground truth — synth entries are reconstructed by scanning section bytes for 4-byte values that fall within the module's image range. ARM instruction encodings, resource sentinels, and coincidental in-range values all collide with real pointers; expect false positives that corrupt embedded constants when consumers re-relocate the PE. Default (`--fs=raw`) skips synth entirely and sets `IMAGE_FILE_RELOCS_STRIPPED` so loaders fail loud rather than apply a faulty table.
>
> **Shared-RVA modules are routed separately.** CE allows two `o32_rom` records to share the same `rva` (a writable RAM-mapped section and a read-only ROM-mapped section overlaid at the same link-time slot, never live simultaneously). PE format requires distinct `VirtualAddress`es per section, so these modules go to `<out>/fs__bad_overlaps/` with original RVAs preserved. The PE container is technically PE-spec invalid (Windows PE loader rejects); IDA, Ghidra and `objdump` parse it. Original section layout (including `realaddr` for split-address sections) is in `rom_meta.json`'s `modules[i].sections[]`.
>
> Other stages (B000FF/NB0 parsing, XIP PE reconstruction, LZX/XPRESS decompression, IMGFS walk, RGU→REG conversion) are documented format parsing and should be correct in principle, but **have not been independently verified** against a reference implementation. Treat all output as best-effort.

## Features

- **B000FF** (sectioned container) and **NB0** (flat binary) ROM formats
- **XIP modules** with LZX (CE 4+) and CE3 BIN (Pocket PC 2000) decompression, and PE32 reconstruction from `e32_rom`/`o32_rom` headers
- **IMGFS filesystem** extraction with Flash Translation Layer page mapping and XPRESS decompression
- **Shared-RVA modules** (where two `o32_rom` records share an `rva` — typically `nk.exe`, `kernel.dll`, `kitl.dll`) routed to `<out>/fs__bad_overlaps/` with original RVAs preserved (PE-spec invalid; IDA/Ghidra parse fine)
- **Split-address sections** (`o32.realaddr ≠ vbase + o32.rva`) preserved in `rom_meta.json`'s `modules[i].sections[]` so consumers can set up MMU + section init faithfully
- **Relocation fixup** for XIP PEs (heuristic mode only): patches split-address references (`o32_realaddr`) and synthesizes `.reloc` sections by scanning for absolute references
- **Import table repair** (heuristic mode only): overwrites ROM-baked IAT entries with original ILT ordinal/name hints
- **Directory structure** from `initflashfiles.dat` (WM5+) or `initobj.dat` (CE3 / WM2003)
- **Registry** extraction: `.rgu` → UTF-8 `.reg` (WM5+), `.hv` preserved verbatim (WM5+), and `default.fdf` binary boot registry → `.reg` (CE3 / WM2003)
- **`rom_meta.json`** with ROMHDR fields (including `ulCopyEntries`/`ulCopyOffset`/`pExtensions`), parsed `copy_table[]` (`{src, dst, copy_len, dest_len}` per entry), ROMPID extension chain, module/file inventory, per-module original `o32_rom` records (`sections[]`), and `romhdr_va` (the value at `physfirst+0x44` per `romldr.h`'s `ROM_TOC_POINTER_OFFSET`, populated across CE3..CE7)

## Modes

`--fs=MODE` controls filesystem reconstruction:

- **`raw`** (default). Each module emitted as a PE under `<out>/fs/Windows/` with bytes verbatim from ROM at original link-time RVAs. Most modules emit strict-conforming PEs; modules with shared-RVA sections (typically `nk.exe`, sometimes `kernel.dll` / `kitl.dll` and a few drivers — 1–4 per ROM) go to `<out>/fs__bad_overlaps/` instead, with original RVAs preserved. Section runtime layout (including `realaddr`) is in `rom_meta.json`'s `modules[i].sections[]`.
- **`heuristic`**. `raw` + synthesize `.reloc` + un-rebase DLLs to `ImageBase=0x10000000` + IAT bound→unbound. The `.reloc` synth has structural false positives (ARM literal pools, resource sentinels, coincidental in-range constants collide with real pointers); not recommended for production.
- **`no`**. Skip filesystem reconstruction entirely. Output is `rom_meta.json` + `Sections/` only — no `fs/`, no `fs__bad_overlaps/`, no `Registry/`, no `attributes.ini`.

`--sections=MODE` controls the `Sections/` folder:

- **`only-overlapping`** (default). Emit only the byte ranges consumers need without `fs/` — shared-RVA module section data (`o32.dataptr` ranges) plus the IMGFS region (when present). Smallest output; suitable for consumers driving runtime synthesis from `rom_meta.json` + `Sections/`.
- **`full`**. B000FF: one file per ROM section (native layout). NB0: one file with the entire flat kernel-VA image. Suitable for full reverse engineering or recovering bootloaders / boot images that have no ECEC marker.

## Usage

```
python extract_wince_rom.py [--fs=MODE] [--sections=MODE] <image.BIN|.nb0> [...]
```

Or place `.BIN`/`.nb0` files next to the script and run without arguments.

Output goes to a directory named after the image (e.g. `WM5_PPC_USA/`):

```
<image-name>/
  fs/                  reconstructed CE filesystem (skipped when --fs=no)
    Windows/           PEs and verbatim non-module files
    Program Files/     placed per initflashfiles.dat / initobj.dat
    My Documents/
    ...
  fs__bad_overlaps/    PEs with shared-RVA sections (originals preserved,
                       PE-spec invalid). For IDA / Ghidra. Skipped when
                       --fs=no or no modules require routing.
  Sections/            kernel-VA byte dumps. Per --sections flag:
                       only-overlapping (default) emits only what fs/ can't
                       cover; full emits the native B000FF section table or
                       the entire NB0 flat image.
  Registry/            .rgu / .hv / default.fdf and converted .reg files
                       (skipped when --fs=no)
  attributes.ini       CE filesystem attribute bits + FILETIME per path
                       (skipped when --fs=no)
  rom_meta.json        ROMHDR / TOC / FILES / ROMPID / per-module
                       sections[] (original o32_rom records: vsize, rva,
                       psize, dataptr, realaddr, flags) / copy_table
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
