# extract-wince-rom

Decomposes Windows CE ROM images (.BIN, .nb0) into smallest chunks: PE executables, media, registry, directory structure, and a `rom_meta.json` describing the ROMHDR / TOC / FILES / ROMPID metadata.

Targets Microsoft Device Emulator images and OEM dumps from Pocket PC 2000 through Windows Phone 7, including Zune OS (CE 5.0 / CE 6.0) firmware.

> [!WARNING]
> **`.reloc` synthesis is inherently approximate** and is **off by default**. It runs only under `--fs=heuristic`. The ROM builder strips the original base-relocation directory, so there is no ground truth — synth entries are reconstructed by scanning section bytes for 4-byte values that fall within the module's image range. ARM instruction encodings, resource sentinels, and coincidental in-range values all collide with real pointers; expect false positives that corrupt embedded constants when consumers re-relocate the PE. Default (`--fs=raw`) skips synth entirely and sets `IMAGE_FILE_RELOCS_STRIPPED` so loaders fail loud rather than apply a faulty table.
>
> Other stages (B000FF/NB0 parsing, XIP PE reconstruction, LZX/XPRESS decompression, IMGFS walk, RGU→REG conversion) are documented format parsing and should be correct in principle, but **have not been independently verified** against a reference implementation. Treat all output as best-effort.

## Features

- **B000FF** (sectioned container) and **NB0** (flat binary) ROM formats
- **XIP modules** with LZX (CE 4+) and CE3 BIN (Pocket PC 2000) decompression, and PE32 reconstruction from `e32_rom`/`o32_rom` headers
- **IMGFS filesystem** extraction with Flash Translation Layer page mapping and XPRESS decompression
- **Every module emits a PE-spec valid container with an appended `.cerom` section** carrying the per-module CE metadata PE format can't natively encode. See [The `.cerom` section](#the-cerom-section) for the format spec.
- **Relocation fixup** for XIP PEs (heuristic mode only): patches split-address references (`o32_realaddr`) and synthesizes `.reloc` sections by scanning for absolute references
- **Import table repair** (heuristic mode only): overwrites ROM-baked IAT entries with original ILT ordinal/name hints
- **Directory structure** from `initflashfiles.dat` (WM5+) or `initobj.dat` (CE3 / WM2003)
- **Registry** extraction: `.rgu` → UTF-8 `.reg` (WM5+), `.hv` preserved verbatim (WM5+), and `default.fdf` binary boot registry → `.reg` (CE3 / WM2003)
- **`rom_meta.json`** carries only cross-module / ROM-level data: ROMHDR fields (including `ulCopyEntries`/`ulCopyOffset`/`pExtensions`), parsed `copy_table[]`, ROMPID extension chain, file (non-module) inventory, a thin module manifest (`{name, shared_rva}` per module), and `romhdr_va`. Per-module CE metadata lives in each module's `.cerom` section, not here.

## The `.cerom` section

Every PE under `fs/Windows/` ships an appended `.cerom` section carrying per-module CE metadata that PE format can't natively describe. CE-aware consumers parse it; PE tools that don't know about it (IDA, Ghidra, objdump, the Windows PE loader) just ignore the section.

### What it carries

Two kinds of per-module data:

1. **TOCentry block** (always present). The 32-byte `TOCentry` struct fields the kernel reads when walking the ROM's table of contents at boot — `e32_offset`, `o32_offset`, `name_offset`, `load_va`, `file_size`, `attributes`, `filetime`, plus the original `e32_rom.vsize`. Consumers reach this without going through `Sections/`.
2. **Original `o32_rom` records + shadow section bytes** (only when needed). PE format has one `VirtualAddress` per section header and no `realaddr` field. Two CE patterns can't be encoded in a standard PE container:
    - **Shared-RVA**: two `o32_rom` records claim the same `rva` (writable RAM-mapped overlaid on read-only ROM-mapped, never live simultaneously). Romimage allows it; PE doesn't.
    - **Split-address**: `o32.realaddr ≠ vbase + o32.rva` (the kernel's MMU maps the section at a runtime VA different from its link-time slot).

   For modules with either pattern, `.cerom` carries the full `o32_rom` array. For shared-RVA, the second record's bytes are embedded inside `.cerom` too (PE section table only has room for one of the two). Pure modules emit `n_objects = 0`.

### Format

Section name: `.cerom`. Flags: `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ` (`0x42000040`). Appended at the next `0x1000`-aligned RVA past the highest existing section. All fields little-endian.

```c
struct cerom_hdr {              // 0x18 bytes
    uint32 magic;               // 'CER1' = 0x31524543
    uint32 version;             // 1
    uint32 hdr_size;            // 0x18
    uint32 n_objects;           // 0 for pure modules, else e32.objcnt
    uint32 obj_size;            // 0x24
    uint32 toc_off;             // offset of cerom_toc within the blob
};

struct cerom_obj {              // 0x24 bytes per o32_rom record
    uint32 vsize;               // o32_vsize
    uint32 rva;                 // o32_rva (link-time RVA)
    uint32 psize;               // o32_psize
    uint32 dataptr;             // o32_dataptr (kernel-VA in the original ROM)
    uint32 realaddr;            // o32_realaddr (runtime VA after MMU map)
    uint32 flags;               // o32_flags
    uint32 is_shadow;           // 0 = primary (PE section header at `rva`
                                //   has these bytes)
                                // 1 = shadow (different o32 owns the PE
                                //   section at `rva`; this one's bytes -
                                //   if any - are at shadow_off below)
    uint32 shadow_off;          // offset within .cerom of shadow bytes,
                                //   or 0 (primary, or BSS-only shadow
                                //   with psize == 0)
    uint32 shadow_size;         // psize when bytes are embedded, 0 otherwise
};

struct cerom_toc {              // 0x24 bytes
    uint32 e32_offset;          // TOCentry.ulE32Offset      (0 for IMGFS)
    uint32 o32_offset;          // TOCentry.ulO32Offset      (0 for IMGFS)
    uint32 name_offset;         // TOCentry.lpszFileName VA  (0 for IMGFS)
    uint32 load_va;             // TOCentry.ulLoadOffset     (0 for IMGFS)
    uint32 file_size;           // TOCentry.nFileSize        (0 for IMGFS)
    uint32 attributes;          // TOCentry.dwFileAttributes / IMGFS attrs
    uint32 filetime_lo;
    uint32 filetime_hi;
    uint32 e32_vsize;           // original e32_rom.vsize. PE.SizeOfImage
                                //   may exceed this since `.cerom` is
                                //   appended past the original image.
};

// followed by shadow byte data (concatenated, indexed by cerom_obj.shadow_off)
```

### Size per module

| Module shape                      | `.cerom` content                       | Size            |
|-----------------------------------|----------------------------------------|-----------------|
| Pure (no shared-RVA, no split)    | header + TOC                           | `0x3C` bytes    |
| Shared-RVA or split-address       | header + TOC + `cerom_obj[]`           | `0x3C + n×0x24` |
| Shared-RVA with shadow bytes      | + concatenated shadow blobs            | + Σ shadow_size |

### Consuming it

```python
pe    = open("fs/Windows/<name>")
cerom = parse_cerom(pe.section('.cerom').data)

# Per-module CE metadata, always available:
toc = cerom.toc                   # e32_offset, o32_offset, name_offset,
                                  # load_va, file_size, attributes,
                                  # filetime_lo, filetime_hi, e32_vsize

# Original o32_rom records, only when shared-RVA or split-address:
for obj in cerom.objs:            # empty list for pure modules
    if obj.is_shadow and obj.shadow_size:
        bytes_at_runtime = cerom.raw[obj.shadow_off : obj.shadow_off + obj.shadow_size]
    else:
        bytes_at_runtime = pe.section_at_rva(obj.rva).data
    # place at obj.realaddr in the target address space
```

The reference Python implementation lives in [`winmob_extract/pe/cerom.py`](winmob_extract/pe/cerom.py).

## Modes

`--fs=MODE` controls filesystem reconstruction:

- **`raw`** (default). Each module emits a single PE-spec valid PE under `<out>/fs/Windows/<name>` with bytes verbatim from ROM at original link-time RVAs, plus a `.cerom` section ([format above](#the-cerom-section)) carrying CE metadata.
- **`heuristic`**. `raw` + synthesize `.reloc` + un-rebase DLLs to `ImageBase=0x10000000` + IAT bound→unbound. The `.reloc` synth has structural false positives (ARM literal pools, resource sentinels, coincidental in-range constants collide with real pointers); not recommended for production.
- **`no`**. Skip filesystem reconstruction entirely. Output is `rom_meta.json` + `Sections/` only — no `fs/`, no `Registry/`, no `attributes.ini`.

`--sections=MODE` controls the `Sections/` folder:

- **`non-module`** (default). Emit only what's *not* in any module's PE — bootloaders, ROMHDR / TOC / FILESentry / COPYentry / ROMPID kernel structures, the IMGFS region (when present), strings, padding. Each per-module byte range is already reachable through that module's PE in `fs/Windows/`, so this folder excludes them. Smallest output.
- **`full`**. B000FF: one file per ROM section (native layout). NB0: one file with the entire flat kernel-VA image. Suitable for full reverse engineering or recovering bootloaders / boot images that have no ECEC marker.

## Usage

```
python extract_wince_rom.py [--fs=MODE] [--sections=MODE] [-o PATH] <image.BIN|.nb0>
```

`-o PATH` / `--output-dir=PATH` overrides the output directory. Default:
`<dir-of-input>/<basename>/` (e.g. `C:\data\img.bin` → `C:\data\img\`):

```
<image-name>/
  fs/                  reconstructed CE filesystem (skipped when --fs=no)
    Windows/           every module as a PE-spec valid PE with an
                       appended `.cerom` section (see above)
    Program Files/     placed per initflashfiles.dat / initobj.dat
    My Documents/
    ...
  Sections/            kernel-VA byte dumps for content not covered by
                       any module's PE (bootloader, ROMHDR-region kernel
                       structs, IMGFS region, ...). Per --sections flag:
                       non-module (default) emits the complement
                       of module dataptr ranges; full emits the native
                       B000FF section table or the entire NB0 flat image.
  Registry/            .rgu / .hv / default.fdf and converted .reg files
                       (skipped when --fs=no)
  attributes.ini       CE filesystem attribute bits + FILETIME per path
                       (skipped when --fs=no)
  rom_meta.json        Cross-module / ROM-level metadata only: ROMHDR,
                       copy_table, ROMPID chain, file inventory, thin
                       module manifest ({name, shared_rva}), romhdr_va.
                       Per-module CE metadata lives in each PE's
                       `.cerom` section.
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
