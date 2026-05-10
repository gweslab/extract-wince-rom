"""CE ROM extension section ('.cerom').

Every module emits a `.cerom` section so per-module CE metadata is
always reachable from the PE container. Two layers of content:

- TOCentry-derived per-module fields (e32_offset, o32_offset,
  name_offset, load_va, file_size, attributes, filetime, e32_vsize).
  Always present.
- Original o32_rom records (vsize, rva, psize, dataptr, realaddr, flags)
  plus shadow records for shared-RVA modules where multiple o32
  records claim the same rva (with shadow section bytes concatenated
  after the entry array). Present only when the module has a
  shared-RVA collision or a split-address section - cases where PE
  format can't describe the layout. Pure modules emit `n_objects = 0`.

A CE kernel emulator (or any tool that needs the runtime-faithful
module layout) walks .cerom; tools that only understand standard PE
(IDA, Ghidra, objdump, the Windows PE loader) ignore it and see a
normal PE.

Layout (little-endian, all uint32 unless noted):

    struct cerom_hdr {            // 0x18 bytes
        uint32 magic;             // 'CER1' = 0x31524543
        uint32 version;           // 1
        uint32 hdr_size;          // 0x18
        uint32 n_objects;
        uint32 obj_size;          // 0x20
        uint32 toc_off;           // offset of cerom_toc (0 = absent)
    };

    struct cerom_obj {            // 0x24 bytes per o32_rom record
        uint32 vsize;             // o32_vsize
        uint32 rva;               // o32_rva
        uint32 psize;             // size of shipped bytes (== vsize when
                                  //   decompressed, original o32_psize
                                  //   otherwise)
        uint32 dataptr;           // o32_dataptr (kernel-VA in original ROM)
        uint32 realaddr;          // o32_realaddr (runtime VA after MMU map)
        uint32 flags;             // o32_flags with IMAGE_SCN_COMPRESSED
                                  //   (0x2000) cleared if the section was
                                  //   decompressed during extraction
        uint32 is_shadow;         // 0 = primary (this o32's bytes live in
                                  //   the PE section table at `rva`),
                                  // 1 = shadow (a different o32 owns the
                                  //   PE section header at `rva`; this
                                  //   one's bytes - if any - are at
                                  //   shadow_off below)
        uint32 shadow_off;        // offset within .cerom of shadow bytes,
                                  //   or 0 when no bytes are embedded
                                  //   (primary, or BSS-only shadow with
                                  //   psize == 0)
        uint32 shadow_size;       // size of shadow bytes (== psize when
                                  //   embedded, 0 otherwise)
    };

    struct cerom_toc {            // 0x24 bytes (36)
        uint32 e32_offset;        // TOCentry.ulE32Offset      (0 for IMGFS)
        uint32 o32_offset;        // TOCentry.ulO32Offset      (0 for IMGFS)
        uint32 name_offset;       // TOCentry.lpszFileName VA  (0 for IMGFS)
        uint32 load_va;           // TOCentry.ulLoadOffset     (0 for IMGFS)
        uint32 file_size;         // TOCentry.nFileSize        (0 for IMGFS)
        uint32 attributes;        // TOCentry.dwFileAttributes / IMGFS attrs
        uint32 filetime_lo;
        uint32 filetime_hi;
        uint32 e32_vsize;         // original e32_rom.vsize (always real;
                                  //   PE.SizeOfImage may exceed this
                                  //   because the .cerom section is
                                  //   appended past the original image)
    };

    // shadow byte data (concatenated, indexed by cerom_obj.shadow_off)
"""

import struct


CEROM_SECTION_NAME = b'.cerom\x00\x00'
CEROM_MAGIC        = 0x31524543   # 'CER1' little-endian
CEROM_VERSION      = 1
CEROM_HDR_SIZE     = 0x18
CEROM_OBJ_SIZE     = 0x24
CEROM_TOC_SIZE     = 0x24

# IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ
CEROM_SECTION_FLAGS = 0x42000040


def build_cerom_blob(o32_records, primary_indices, toc, get_shadow_bytes):
    """Build a .cerom binary blob.

    o32_records:     list of (vsize, rva, psize, dataptr, realaddr, flags)
                     tuples - all o32_rom records for the module,
                     including shadows for shared-RVA cases.
    primary_indices: set of indices in o32_records whose bytes are in
                     the standard PE section table (their rva is the
                     visible one). Other indices are shadows; their
                     bytes are embedded in .cerom.
    toc:             dict with cerom_toc fields. Pass an all-zero dict
                     plus the real e32_vsize for IMGFS modules without
                     TOCentries.
    get_shadow_bytes: callable(idx) -> bytes for shadow sections with
                     psize > 0. Not called for primary indices or for
                     shadow indices with psize == 0.
    """
    n = len(o32_records)
    obj_off    = CEROM_HDR_SIZE
    toc_off    = obj_off + n * CEROM_OBJ_SIZE
    shadow_off = toc_off + CEROM_TOC_SIZE

    shadows = {}  # idx -> (off, bytes)
    cur = shadow_off
    for i, (vsize, rva, psize, dataptr, realaddr, flags) in enumerate(o32_records):
        if i not in primary_indices and psize > 0:
            data = get_shadow_bytes(i)
            shadows[i] = (cur, data)
            cur += len(data)

    blob = bytearray(cur)

    struct.pack_into('<6I', blob, 0,
        CEROM_MAGIC, CEROM_VERSION, CEROM_HDR_SIZE,
        n, CEROM_OBJ_SIZE, toc_off)

    for i, (vsize, rva, psize, dataptr, realaddr, flags) in enumerate(o32_records):
        s_off = shadows.get(i, (0, b''))[0]
        s_size = len(shadows[i][1]) if i in shadows else 0
        is_shadow = 0 if i in primary_indices else 1
        struct.pack_into('<9I', blob, obj_off + i * CEROM_OBJ_SIZE,
            vsize, rva, psize, dataptr, realaddr, flags,
            is_shadow, s_off, s_size)

    struct.pack_into('<9I', blob, toc_off,
        toc.get('e32_offset', 0), toc.get('o32_offset', 0),
        toc.get('name_offset', 0), toc.get('load_va', 0),
        toc.get('file_size', 0), toc.get('attributes', 0),
        toc.get('filetime_lo', 0), toc.get('filetime_hi', 0),
        toc.get('e32_vsize', 0))

    for i, (off, data) in shadows.items():
        blob[off:off + len(data)] = data

    return bytes(blob)


def pick_primary_indices(o32_records):
    """For each rva-group in o32_records, pick the index whose bytes
    should appear in the standard PE section table at that rva.

    Returns a set of indices (one per distinct rva).

    Selection rule: prefer the o32 record whose `psize > 0` over BSS-
    only entries, since the PE section table at that rva should expose
    real bytes to standard PE consumers (IDA, Ghidra, objdump). On a
    tie (multiple records with psize > 0 sharing one rva — rare), pick
    the lowest index for determinism.
    """
    by_rva = {}
    for i, (vsize, rva, psize, dataptr, realaddr, flags) in enumerate(o32_records):
        by_rva.setdefault(rva, []).append(i)
    primaries = set()
    for rva, indices in by_rva.items():
        with_bytes = [i for i in indices if o32_records[i][2] > 0]
        primaries.add(with_bytes[0] if with_bytes else indices[0])
    return primaries
