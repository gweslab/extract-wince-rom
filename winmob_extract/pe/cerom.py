"""CE ROM extension section ('.cerom').

Every module emits a `.cerom` section so per-module CE metadata is
always reachable from the PE container. Two layers of content:

- TOCentry-derived per-module fields (cerom_toc). Always present.
- cerom_obj[] records carrying the full o32_rom array. Present only
  for shared-RVA modules (PE format allows one section per RVA) and
  split-address modules (o32_realaddr differs from vbase+rva). Pure
  modules emit `n_objects = 0`.

cerom_obj separates original-ROM fields (psize, flags - verbatim from
BIN, never overwritten) from after-extraction fields
(psize_after_extraction, flags_after_extraction - describing the bytes
on disk). Consumers read whichever matches their use case.

Standard PE tools (IDA, Ghidra, objdump, Windows PE loader) ignore
.cerom and see a normal PE.

Layout (little-endian, all uint32 unless noted):

    struct cerom_hdr {            // 0x18 bytes
        uint32 magic;             // 'CER1' = 0x31524543
        uint32 version;           // 1
        uint32 hdr_size;          // 0x18
        uint32 n_objects;
        uint32 obj_size;          // 0x2C
        uint32 toc_off;           // offset of cerom_toc (0 = absent)
    };

    struct cerom_obj {                // 0x2C bytes per o32_rom record
        uint32 vsize;                 // o32_vsize
        uint32 rva;                   // o32_rva
        uint32 psize;                 // o32_psize (verbatim from BIN)
        uint32 dataptr;               // o32_dataptr (kernel-VA in ROM)
        uint32 realaddr;              // o32_realaddr (runtime VA after MMU map)
        uint32 flags;                 // o32_flags (verbatim from BIN)
        uint32 is_shadow;             // 0 = primary, 1 = shadow
        uint32 shadow_off;            // offset within .cerom of shadow bytes,
                                      //   0 when no bytes are embedded
        uint32 shadow_size;           // size of shadow bytes, 0 otherwise
        uint32 flags_after_extraction; // flags matching the bytes shipped:
                                      //   IMAGE_SCN_COMPRESSED (0x2000) cleared
                                      //   when the section was decompressed
                                      //   during extraction
        uint32 psize_after_extraction; // size of bytes on disk: == vsize when
                                      //   decompressed, == psize otherwise
    };

    struct cerom_toc {            // 0x24 bytes
        uint32 e32_offset;        // TOCentry.ulE32Offset      (0 for IMGFS)
        uint32 o32_offset;        // TOCentry.ulO32Offset      (0 for IMGFS)
        uint32 name_offset;       // TOCentry.lpszFileName VA  (0 for IMGFS)
        uint32 load_va;           // TOCentry.ulLoadOffset     (0 for IMGFS)
        uint32 file_size;         // TOCentry.nFileSize        (0 for IMGFS)
        uint32 attributes;        // TOCentry.dwFileAttributes / IMGFS attrs
        uint32 filetime_lo;
        uint32 filetime_hi;
        uint32 e32_vsize;         // original e32_rom.vsize
    };

    // shadow byte data (concatenated, indexed by cerom_obj.shadow_off)
"""

import struct


CEROM_SECTION_NAME = b'.cerom\x00\x00'
CEROM_MAGIC        = 0x31524543   # 'CER1' little-endian
CEROM_VERSION      = 1
CEROM_HDR_SIZE     = 0x18
CEROM_OBJ_SIZE     = 0x2C
CEROM_TOC_SIZE     = 0x24

# IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ
CEROM_SECTION_FLAGS = 0x42000040


def build_cerom_blob(o32_records, extraction_state, primary_indices, toc,
                     get_shadow_bytes):
    """Build a .cerom binary blob.

    o32_records:      list of (vsize, rva, psize, dataptr, realaddr, flags)
                      tuples - original o32_rom records verbatim from the BIN.
    extraction_state: list parallel to o32_records, each entry is
                      (flags_after_extraction, psize_after_extraction).
    primary_indices:  set of indices in o32_records whose bytes are in
                      the standard PE section table.
    toc:              dict with cerom_toc fields.
    get_shadow_bytes: callable(idx) -> bytes for shadow sections.
    """
    n = len(o32_records)
    obj_off    = CEROM_HDR_SIZE
    toc_off    = obj_off + n * CEROM_OBJ_SIZE
    shadow_off = toc_off + CEROM_TOC_SIZE

    shadows = {}
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
        flags_ae, psize_ae = extraction_state[i]
        struct.pack_into('<11I', blob, obj_off + i * CEROM_OBJ_SIZE,
            vsize, rva, psize, dataptr, realaddr, flags,
            is_shadow, s_off, s_size,
            flags_ae, psize_ae)

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
    """For each rva-group, pick the index whose bytes appear in the PE
    section table at that rva. Prefers `psize > 0` over BSS-only entries;
    ties pick the lowest index."""
    by_rva = {}
    for i, (vsize, rva, psize, dataptr, realaddr, flags) in enumerate(o32_records):
        by_rva.setdefault(rva, []).append(i)
    primaries = set()
    for rva, indices in by_rva.items():
        with_bytes = [i for i in indices if o32_records[i][2] > 0]
        primaries.add(with_bytes[0] if with_bytes else indices[0])
    return primaries
