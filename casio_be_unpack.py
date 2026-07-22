#!/usr/bin/env python3
"""Casio BE-300 / BE-500 NAND blob -> OS image for extract_wince_rom.py

Usage:  python casio_be_unpack.py <nand_dump.bin> <out_os.bin>
Then:   python extract_wince_rom.py --machine mips -o <outdir> <out_os.bin>

Layout of the NAND blob: a region table of 512-byte-sector records at offset 0
(FF*8 + u32 start_sector + u32 length_sectors), then the regions it names -
region 1 the bootloader (plain B000FF), region 2 the OS (LZSS-compressed
B000FF), region 3 the user store.

Compression is LZSS with a 4096-byte zero-filled ring starting at write
position 4078: one flag byte per 8 tokens, LSB-first, bit set = literal byte,
bit clear = a 2-byte match where pos = b1 | ((b2 & 0xF0) << 4) and
length = (b2 & 0x0F) + 3. The region's first byte is the first flag byte.
"""
import struct
import sys

RING = 4096
RING_START = 4078
SECTOR = 512
TABLE_SIZE = 0x4000


def regions(data):
    out = []
    for off in range(0, TABLE_SIZE, 16):
        if data[off:off + 8] != b'\xff' * 8:
            continue
        start, length = struct.unpack_from('<2I', data, off + 8)
        if start == 0xFFFFFFFF:
            continue
        out.append((start * SECTOR, length * SECTOR))
    return out


def lzss_decompress(src, out_size):
    out = bytearray()
    ring = bytearray(RING)
    rp = RING_START
    si = 0
    n = len(src)
    while si < n and len(out) < out_size:
        flag = src[si]
        si += 1
        for bit in range(8):
            if si >= n or len(out) >= out_size:
                break
            if flag >> bit & 1:
                c = src[si]
                si += 1
                out.append(c)
                ring[rp] = c
                rp = (rp + 1) & (RING - 1)
            else:
                if si + 1 >= n:
                    return bytes(out)
                b1, b2 = src[si], src[si + 1]
                si += 2
                pos = b1 | ((b2 & 0xF0) << 4)
                for k in range((b2 & 0x0F) + 3):
                    c = ring[(pos + k) & (RING - 1)]
                    out.append(c)
                    ring[rp] = c
                    rp = (rp + 1) & (RING - 1)
    return bytes(out)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    data = open(sys.argv[1], 'rb').read()
    regs = regions(data)
    if len(regs) < 3:
        print(f"ERROR: expected at least 3 regions, found {len(regs)}")
        return 1
    covered = sum(length for _, length in regs)
    print("regions: " + ", ".join(f"0x{a:X}+0x{l:X}" for a, l in regs))
    print(f"table covers 0x{covered:X}, file is 0x{len(data):X}"
          f" -> {'consistent' if covered == len(data) else 'MISMATCH'}")

    start, length = regs[2]
    packed = data[start:start + length]
    head = lzss_decompress(packed, 32)
    if head[:7] != b'B000FF\n':
        print("ERROR: region 2 did not decompress to a B000FF image")
        return 1
    image_start, image_length = struct.unpack_from('<2I', head, 7)
    image = lzss_decompress(packed, image_length)
    open(sys.argv[2], 'wb').write(image)
    print(f"OS image: start=0x{image_start:08X} length=0x{image_length:X} "
          f"({length} -> {len(image)} bytes, {len(image) / length:.2f}x)")
    print(f"wrote {sys.argv[2]}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
