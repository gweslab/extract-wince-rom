"""CE binary boot registry parser (default.fdf -> Windows REGEDIT4 .reg).

Used by Pocket PC 2000 (CE 3) and Windows Mobile 2003 (CE 4.x). Both share
the same binary registry format. Determined empirically from WM2003SE
default.fdf (310,827 bytes) and IPAQROM177 default.fdf (177,749 bytes),
both parsed exactly to byte boundary. No external spec used.

  Header (8 bytes total):
    4 bytes : magic 'B274831D'
    u32     : file size (matches len(raw) exactly)

  Records flow until EOF. Each record:
    u16  : payload_size (bytes following the type word)
    u16  : type           1 = KEY, 2 = VALUE

    If type == 1 (KEY):
      u16  : reserved (= 0)
      u16  : path_chars (UTF-16 chars including trailing NUL)
      WCHAR path[path_chars]

    If type == 2 (VALUE) - applies to the most recently seen KEY:
      u16  : value_type    REG_SZ=1, REG_EXPAND_SZ=2, REG_BINARY=3,
                           REG_DWORD=4, REG_MULTI_SZ=7, 0x15=CE-specific
                           (looks like REG_MUI_SZ - localized string ref).
      u16  : name_chars (UTF-16 chars including trailing NUL)
      u16  : data_bytes
      WCHAR name[name_chars]
      BYTE  data[data_bytes]

A value name of "Default" maps to the registry's default (unnamed) value
(CE convention). All keys are emitted under HKEY_LOCAL_MACHINE.
"""

from .util import u16, u32


CE_FDF_MAGIC = b'\xB2\x74\x83\x1D'


def _reg_escape(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')


def _reg_hex_bytes(data):
    return ','.join(f'{b:02x}' for b in data)


def parse_fdf_registry(raw):
    """Parse a CE / WM2003 default.fdf binary boot registry.

    Returns a list of records as ('KEY', path) / ('VALUE', name, value_type, data).
    Returns None if the magic does not match.
    """
    if len(raw) < 8 or raw[:4] != CE_FDF_MAGIC:
        return None
    records = []
    off = 8  # skip 4-byte magic + 4-byte file-size DWORD
    while off + 4 <= len(raw):
        size = u16(raw, off)
        rtype = u16(raw, off + 2)
        body_off = off + 4
        body_end = body_off + size
        if body_end > len(raw):
            break
        if rtype == 1:
            if size < 4:
                break
            pchars = u16(raw, body_off + 2)
            path_end = body_off + 4 + pchars * 2
            if path_end > body_end:
                break
            path = raw[body_off + 4:path_end].decode(
                'utf-16-le', errors='replace').rstrip('\x00')
            records.append(('KEY', path))
        elif rtype == 2:
            if size < 6:
                break
            vtype = u16(raw, body_off)
            nchars = u16(raw, body_off + 2)
            dbytes = u16(raw, body_off + 4)
            name_end = body_off + 6 + nchars * 2
            data_end = name_end + dbytes
            if data_end > body_end:
                break
            name = raw[body_off + 6:name_end].decode(
                'utf-16-le', errors='replace').rstrip('\x00')
            data = bytes(raw[name_end:data_end])
            records.append(('VALUE', name, vtype, data))
        else:
            # Unknown record type - stop rather than emit garbage
            break
        off = body_end
    return records


def fdf_to_reg_text(records):
    """Convert parsed default.fdf records to Windows REGEDIT4 text format."""
    lines = ['REGEDIT4', '']
    for rec in records:
        if rec[0] == 'KEY':
            lines.append(f'[HKEY_LOCAL_MACHINE\\{rec[1]}]')
        else:
            _, name, vtype, data = rec
            name_field = '@' if name == 'Default' else f'"{_reg_escape(name)}"'
            if vtype == 1:  # REG_SZ
                txt = data.decode('utf-16-le', errors='replace').rstrip('\x00')
                lines.append(f'{name_field}="{_reg_escape(txt)}"')
            elif vtype == 4 and len(data) == 4:  # REG_DWORD
                v = u32(data, 0)
                lines.append(f'{name_field}=dword:{v:08x}')
            elif vtype == 3:  # REG_BINARY
                lines.append(f'{name_field}=hex:{_reg_hex_bytes(data)}')
            else:
                # REG_EXPAND_SZ (2), REG_MULTI_SZ (7), CE REG_MUI_SZ (0x15),
                # unusual REG_DWORD lengths, unknown types
                lines.append(f'{name_field}=hex({vtype:x}):{_reg_hex_bytes(data)}')
    lines.append('')
    return '\n'.join(lines)
