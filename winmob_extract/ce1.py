import os

from .util import u16, u32, read_ascii, safe_filename, ROMHDR_SIZE
from .compress import ce1_lzw_decompress
from .pe.ce1 import reconstruct_pe_ce1
from .rom_structs import _hex, _hex16

CE1_TOCENTRY_SIZE = 0x130
CE1_FILEENTRY_SIZE = 0x12C
PAGE_SIZE = 0x1000


def _romhdr(data, off):
    if off < 0 or off + ROMHDR_SIZE > len(data):
        return None
    physfirst = u32(data, off + 8)
    physlast = u32(data, off + 12)
    nummods = u32(data, off + 16)
    numfiles = u32(data, off + 48)
    if not (0x80000000 <= physfirst < 0xC0000000):
        return None
    if not (physfirst < physlast <= physfirst + 0x10000000):
        return None
    if not (1 <= nummods <= 4096) or numfiles > 50000:
        return None
    return dict(off=off, physfirst=physfirst, physlast=physlast,
                nummods=nummods, numfiles=numfiles,
                ulRAMStart=u32(data, off + 20), ulRAMEnd=u32(data, off + 28),
                ulCopyEntries=u32(data, off + 32), ulCopyOffset=u32(data, off + 36),
                usCPUType=u16(data, off + 0x44))


def _toc0_inline_name(data, romhdr_off):
    name = read_ascii(data, romhdr_off + ROMHDR_SIZE + 0x10, 64)
    if not name or any(ord(c) < 0x20 or ord(c) > 0x7E for c in name):
        return ''
    return name


def find_ce1_romhdrs(data):
    cands = []
    for off in range(0, len(data) - ROMHDR_SIZE, 4):
        h = _romhdr(data, off)
        if h is None:
            continue
        name = _toc0_inline_name(data, off)
        if not name:
            continue
        cands.append((h, name))
    if not cands:
        return None, []
    base_va = min(h['physfirst'] for h, _ in cands)
    hdrs = []
    have_nk = False
    for h, name in cands:
        nt_va = u32(data, h['off'] + ROMHDR_SIZE + 0x124)
        nt = nt_va - base_va
        if nt < 0 or nt + 4 > len(data) or data[nt:nt + 4] != b'PE\x00\x00':
            continue
        hdrs.append(h)
        if name.lower() == 'nk.exe':
            have_nk = True
    if not have_nk:
        return None, []
    return base_va, hdrs


def is_ce1_rom(data):
    _, hdrs = find_ce1_romhdrs(data)
    return bool(hdrs)


def _decompress_file(flat, base_va, load_va, comp_size, real_size):
    off = load_va - base_va
    if off < 0 or off + comp_size > len(flat):
        return None
    raw = flat[off:off + comp_size]
    npages = (real_size + PAGE_SIZE - 1) // PAGE_SIZE
    if npages * 4 > comp_size:
        return None
    starts = [u32(raw, i * 4) for i in range(npages)]
    out = bytearray()
    for i in range(npages):
        p_start = starts[i] & 0x7FFFFFFF
        stored = starts[i] & 0x80000000
        p_end = (starts[i + 1] & 0x7FFFFFFF) if i + 1 < npages else comp_size
        want = min(PAGE_SIZE, real_size - i * PAGE_SIZE)
        page = raw[p_start:p_end]
        out.extend(page[:want] if stored else ce1_lzw_decompress(page, want))
    return bytes(out[:real_size])


def extract_ce1(data, out_dir, label="", attr_log=None, fs_mode='raw',
                rom_meta=None):
    skip_fs = (fs_mode == 'no')
    base_va, hdrs = find_ce1_romhdrs(data)
    if not hdrs:
        return 0, 0

    if rom_meta is not None:
        for k in ('modules', 'files', 'rompid', 'copy_table'):
            rom_meta.setdefault(k, [])

    win_dir = os.path.join(out_dir, "fs", "Windows")
    if not skip_fs:
        os.makedirs(win_dir, exist_ok=True)

    used = set()

    def unique(name):
        base = safe_filename(name)
        cand = base
        n = 1
        while cand.lower() in used:
            root, ext = os.path.splitext(base)
            cand = f"{root}.{n}{ext}"
            n += 1
        used.add(cand.lower())
        return cand

    total_mods = total_files = 0
    for h in hdrs:
        print(f"{label}  CE1 XIP @ 0x{h['off']:X}: {h['nummods']} modules, "
              f"{h['numfiles']} files (physfirst=0x{h['physfirst']:08X})")

        if rom_meta is not None and rom_meta.get('romhdr') is None:
            rom_meta['romhdr'] = {
                'physfirst': _hex(h['physfirst']), 'physlast': _hex(h['physlast']),
                'ulRAMStart': _hex(h['ulRAMStart']), 'ulRAMEnd': _hex(h['ulRAMEnd']),
                'ulCopyEntries': h['ulCopyEntries'], 'ulCopyOffset': _hex(h['ulCopyOffset']),
                'usCPUType': _hex16(h['usCPUType']),
            }
            rom_meta['_load_offset'] = base_va

        toc = h['off'] + ROMHDR_SIZE
        files = toc + h['nummods'] * CE1_TOCENTRY_SIZE

        for i in range(h['nummods']):
            e = toc + i * CE1_TOCENTRY_SIZE
            if e + CE1_TOCENTRY_SIZE > len(data):
                break
            attrs = u32(data, e)
            ft = (u32(data, e + 8) << 32) | u32(data, e + 4)
            name = read_ascii(data, e + 0x10, 276)
            nt_va = u32(data, e + 0x124)
            sh_va = u32(data, e + 0x128)
            pe = reconstruct_pe_ce1(data, base_va, nt_va, sh_va)
            if not pe or not name:
                continue
            if not skip_fs:
                with open(os.path.join(win_dir, unique(name)), 'wb') as f:
                    f.write(pe)
            total_mods += 1
            if attr_log is not None:
                attr_log['\\Windows\\' + name] = (attrs, ft)
            if rom_meta is not None:
                rom_meta['modules'].append({'name': name, 'shared_rva': False})

        for i in range(h['numfiles']):
            e = files + i * CE1_FILEENTRY_SIZE
            if e + CE1_FILEENTRY_SIZE > len(data):
                break
            attrs = u32(data, e)
            ft = (u32(data, e + 8) << 32) | u32(data, e + 4)
            real_size = u32(data, e + 0x0C)
            comp_size = u32(data, e + 0x10)
            name = read_ascii(data, e + 0x14, 276)
            load_va = u32(data, e + 0x128)
            if not name or comp_size == 0:
                continue
            payload = _decompress_file(data, base_va, load_va, comp_size, real_size)
            if payload is None or len(payload) != real_size:
                continue
            if not skip_fs:
                with open(os.path.join(win_dir, unique(name)), 'wb') as f:
                    f.write(payload)
            total_files += 1
            if attr_log is not None:
                attr_log['\\Windows\\' + name] = (attrs, ft)
            if rom_meta is not None:
                rom_meta['files'].append({
                    'name': name, 'load_va': _hex(load_va),
                    'real_size': real_size, 'compressed_size': comp_size,
                    'compressed': comp_size != real_size,
                    'attributes': _hex(attrs),
                })

        print(f"{label}    -> {total_mods} modules, {total_files} files")

    return total_mods, total_files
