import struct

from ..util import align, u16, u32
from ..compress import ce1_lzw_decompress
from .cerom import CEROM_SECTION_FLAGS, CEROM_SECTION_NAME, build_cerom_blob

IMAGE_SCN_COMPRESSED = 0x2000
IMAGE_SCN_MEM_WRITE = 0x80000000
FILE_ALIGN = 0x200


def _dos_stub():
    dos = bytearray(0x80)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x80)
    return bytes(dos)


def _primaries(records):
    by_rva = {}
    for i, r in enumerate(records):
        by_rva.setdefault(r[1], []).append(i)
    out = set()
    for rva, idxs in by_rva.items():
        ro = [i for i in idxs
              if records[i][2] > 0 and not (records[i][5] & IMAGE_SCN_MEM_WRITE)]
        wb = [i for i in idxs if records[i][2] > 0]
        out.add(ro[0] if ro else (wb[0] if wb else idxs[0]))
    return out


def reconstruct_pe_ce1(flat, base_va, nt_va, sh_va):
    nt = nt_va - base_va
    if nt < 0 or nt + 24 > len(flat) or flat[nt:nt + 4] != b'PE\x00\x00':
        return None
    nsec = u16(flat, nt + 6)
    opt_size = u16(flat, nt + 0x14)
    sh = sh_va - base_va
    if nsec == 0 or nsec > 96 or sh < 0 or sh + nsec * 40 > len(flat):
        return None

    headers = bytearray(flat[nt:nt + 24 + opt_size])
    sec_align = struct.unpack_from('<I', headers, 24 + 0x20)[0] or 0x1000

    raw_hdrs = []
    records = []
    ext_state = []
    sec_data = []
    for s in range(nsec):
        so = sh + s * 40
        rh = bytearray(flat[so:so + 40])
        vsize, va, raw_size, praw = struct.unpack_from('<4I', rh, 8)
        flags = struct.unpack_from('<I', rh, 0x24)[0]
        data = b''
        flags_ae, psize_ae = flags, raw_size
        if raw_size:
            off = praw - base_va
            if off < 0 or off + raw_size > len(flat):
                return None
            data = flat[off:off + raw_size]
            if flags & IMAGE_SCN_COMPRESSED:
                data = ce1_lzw_decompress(data, vsize)
                flags_ae = flags & ~IMAGE_SCN_COMPRESSED
                psize_ae = len(data)
        raw_hdrs.append(rh)
        records.append((vsize, va, raw_size, praw, 0, flags))
        ext_state.append((flags_ae, psize_ae))
        sec_data.append(bytes(data))

    primaries = _primaries(records)
    needs_cerom = len({r[1] for r in records}) != len(records)

    out = []
    for i in range(nsec):
        if i not in primaries:
            continue
        rh = bytearray(raw_hdrs[i])
        struct.pack_into('<I', rh, 0x24, ext_state[i][0])
        struct.pack_into('<I', rh, 16, len(sec_data[i]))
        out.append([rh, sec_data[i]])

    if needs_cerom:
        cerom = build_cerom_blob(records, ext_state, primaries, {},
                                 lambda i: sec_data[i])
        top = max(records[i][1] + max(records[i][0], len(sec_data[i]))
                  for i in primaries)
        cerom_rva = align(top, sec_align)
        crh = bytearray(40)
        crh[0:8] = CEROM_SECTION_NAME
        struct.pack_into('<4I', crh, 8, len(cerom), cerom_rva, len(cerom), 0)
        struct.pack_into('<I', crh, 0x24, CEROM_SECTION_FLAGS)
        out.append([crh, cerom])
        struct.pack_into('<I', headers, 24 + 0x38,
                         cerom_rva + align(len(cerom), sec_align))

    struct.pack_into('<H', headers, 6, len(out))

    body_off = align(0x80 + len(headers) + len(out) * 40, FILE_ALIGN)
    body = bytearray()
    cur = body_off
    for rh, data in out:
        if data:
            struct.pack_into('<I', rh, 20, cur)
            body.extend(data + b'\x00' * (align(len(data), FILE_ALIGN) - len(data)))
            cur += align(len(data), FILE_ALIGN)
        else:
            struct.pack_into('<I', rh, 20, 0)

    pe = bytearray(_dos_stub())
    pe.extend(headers)
    for rh, _ in out:
        pe.extend(rh)
    pe.extend(b'\x00' * (body_off - len(pe)))
    pe.extend(body)
    return bytes(pe)
