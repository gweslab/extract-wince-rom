"""Shared low-level helpers and CE ROM struct sizes."""

import struct


# Struct sizes (loadbin_nb0.h / loadbin_nb0.cpp)
ROMHDR_SIZE = 84
TOCENTRY_SIZE = 32
FILEENTRY_SIZE = 28
SECTION_HEADER_SIZE = 12


def u16(data, off):
    return struct.unpack_from('<H', data, off)[0]


def u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def read_ascii(data, off, maxlen=256):
    end = data.find(b'\x00', off, off + maxlen)
    if end == -1:
        end = off + maxlen
    return data[off:end].decode('ascii', errors='replace')


def safe_filename(name):
    """Sanitise a filename for the host filesystem."""
    for ch in '\\/:*?"<>|':
        name = name.replace(ch, '_')
    while name.startswith('.'):
        name = '_' + name[1:]
    return name or 'unnamed'


def align(v, a):
    return (v + a - 1) & ~(a - 1)
