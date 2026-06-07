"""Decompression for CE ROM module sections (LZX) and IMGFS data (XPRESS LZ77).

Windows CE uses two LZ77 variants, both MSB-first:

  1) ROM section compression (CeCompress / DecompressBinaryBlock):
     Extended match lengths use a full byte, no nibble sharing.
     Used for compressed XIP module sections (flag 0x2000 in o32_rom).

  2) IMGFS XPRESS compression:
     Extended match lengths use nibble-sharing - consecutive extended
     matches alternate low/high nibbles of a shared byte.
     Used for file data chunks inside IMGFS.

LZX (variant 1's actual format inside .text/.rdata of XIP modules) is
delegated to the `wince_decompr` submodule; the LZ77 implementation below
is only used for IMGFS XPRESS.
"""

import struct

from wince_decompr.wincedecompr import CEDecompressROM as _lzx_decompress_rom


def _lz77_core(src, out_size, nibble_sharing):
    """Core LZ77 decompressor for both CE variants.

    Flag bits are processed MSB-first (bit 31 -> 0).
    Match descriptor: offset = (val >> 3) + 1, base_len = val & 7.
    If base_len == 7, an extended length follows.
    """
    slen = len(src)
    dst = bytearray(out_size)
    si = 0
    di = 0
    nibble_idx = 0  # only used when nibble_sharing is True

    while si < slen and di < out_size:
        if si + 4 > slen:
            break
        flags = struct.unpack_from('<I', src, si)[0]
        si += 4

        for bit in range(31, -1, -1):
            if si >= slen or di >= out_size:
                break

            if not (flags & (1 << bit)):
                # Literal byte
                dst[di] = src[si]
                si += 1
                di += 1
            else:
                # Match reference
                if si + 2 > slen:
                    return bytes(dst[:di])
                val = struct.unpack_from('<H', src, si)[0]
                si += 2
                match_off = (val >> 3) + 1
                match_len = val & 7

                if match_len == 7:
                    if nibble_sharing:
                        # Nibble-sharing: alternate low/high nibbles
                        if nibble_idx == 0:
                            if si >= slen:
                                return bytes(dst[:di])
                            nibble_idx = si
                            match_len = src[si] & 0x0F
                            si += 1
                        else:
                            match_len = src[nibble_idx] >> 4
                            nibble_idx = 0
                    else:
                        # Full byte extension
                        if si >= slen:
                            return bytes(dst[:di])
                        match_len = src[si]
                        si += 1

                    if match_len == 15:
                        if si >= slen:
                            return bytes(dst[:di])
                        match_len = src[si]
                        si += 1
                        if match_len == 255:
                            if si + 2 > slen:
                                return bytes(dst[:di])
                            match_len = struct.unpack_from('<H', src, si)[0]
                            si += 2
                            if match_len == 0:
                                if si + 4 > slen:
                                    return bytes(dst[:di])
                                match_len = struct.unpack_from('<I', src, si)[0]
                                si += 4
                            if match_len < 22:
                                return bytes(dst[:di])
                            match_len -= 22
                        match_len += 15
                    match_len += 7

                match_len += 3
                copy_from = di - match_off

                if copy_from >= 0 and copy_from + match_len <= di:
                    end = min(di + match_len, out_size)
                    n = end - di
                    dst[di:end] = dst[copy_from:copy_from + n]
                    di = end
                else:
                    for _ in range(match_len):
                        if di >= out_size:
                            break
                        p = copy_from
                        copy_from += 1
                        dst[di] = dst[p] if 0 <= p < di else 0
                        di += 1

    return bytes(dst[:di]) if di < out_size else bytes(dst)


def _ce3_bin_decompress_block(src, dst_max):
    """One inner block of the CE3 BIN compression scheme.

    Block format:
      flag byte: 8 tokens, LSB-first; bit 0 = literal, bit 1 = match.
      Literal: read 1 byte, write to output.
      Match: read 1 byte t. low = t & 0xF, high = (t >> 4) & 0xF.
        low == 1 -> short match: length=2, src_pos = di - high - 2.
        low == 0 -> long match : read b1, src_pos = (b1 << 4) | high
                                 (12-bit absolute output offset within block);
                                 read b2, length = b2 + 17.
        low >  1 -> medium match: read b1, src_pos = (b1 << 4) | high;
                                  length = low + 1 (3..16).
      Copy is byte-by-byte from absolute output position (RLE-safe overlap).
    """
    out = bytearray(dst_max)
    si = 0
    di = 0
    slen = len(src)
    while si < slen and di < dst_max:
        flag = src[si]; si += 1
        for bit in range(8):
            if si >= slen or di >= dst_max:
                break
            t = src[si]; si += 1
            if not (flag & (1 << bit)):
                out[di] = t
                di += 1
            else:
                low = t & 0xF
                high = (t >> 4) & 0xF
                if low == 1:
                    length = 2
                    src_pos = di - high - 2
                else:
                    if si >= slen:
                        return bytes(out[:di])
                    b = src[si]; si += 1
                    src_pos = (b << 4) | high
                    if low == 0:
                        if si >= slen:
                            return bytes(out[:di])
                        length = src[si] + 17; si += 1
                    else:
                        length = low + 1
                for k in range(length):
                    if di >= dst_max:
                        break
                    p = src_pos + k
                    # A match near a short final block can reference past the
                    # block's output bound; treat out-of-range as zero rather
                    # than indexing off the end.
                    out[di] = out[p] if 0 <= p < dst_max else 0
                    di += 1
    return bytes(out[:di])


def ce3_bin_decompress(src, out_size, block_bits=12):
    """Decompress a CE3 / Pocket PC 2000 BIN-compressed payload.

    Returns the decompressed bytes (zero-padded to out_size) or None if the
    input doesn't look like a valid CE3 multi-block stream. Outer wrapper:
    3-byte little-endian uncompressed-size header, then num_blocks-1 more
    3-byte block-end offsets, then concatenated independent blocks of up to
    (1 << block_bits) bytes each.
    """
    if len(src) < 3:
        return None
    uncomp_size = src[0] | (src[1] << 8) | (src[2] << 16)
    num_blocks = (uncomp_size >> block_bits) + 2
    if len(src) < 3 * num_blocks:
        return None
    block_size = 1 << block_bits
    out = bytearray()
    prev_end = 3 * num_blocks
    for i in range(1, num_blocks):
        end = src[i*3] | (src[i*3+1] << 8) | (src[i*3+2] << 16)
        if end > len(src) or end < prev_end:
            return None
        block_data = src[prev_end:end]
        remaining = uncomp_size - len(out)
        block_out = _ce3_bin_decompress_block(block_data, min(remaining, block_size))
        out.extend(block_out)
        prev_end = end
    if len(out) < out_size:
        out.extend(b'\x00' * (out_size - len(out)))
    return bytes(out[:out_size])


def ce_rom_decompress(src, out_size):
    """Decompress a CE ROM compressed section.

    Tries LZX first (CE 4+ ROMs). Falls back to the CE3 BIN scheme for older
    Pocket PC 2000 / CE 3 ROMs. Returns `out_size` bytes always (zero-padded
    on partial decompression or total failure) so callers don't need to
    handle short reads.
    """
    dcbuf = bytearray(out_size + 4096)
    try:
        rlen = _lzx_decompress_rom(bytes(src), len(src), dcbuf, out_size, 0, 1, 4096)
    except Exception:
        rlen = -1
    if rlen > 0:
        result = bytes(dcbuf[:rlen])
        if len(result) < out_size:
            result += b'\x00' * (out_size - len(result))
        return result
    ce3 = ce3_bin_decompress(src, out_size)
    if ce3 is not None:
        return ce3
    return b'\x00' * out_size  # fallback: zero-fill on failure


def xpress_decompress(src, out_size):
    """Decompress IMGFS XPRESS data (nibble-sharing extension)."""
    return _lz77_core(src, out_size, nibble_sharing=True)


def try_decompress(chunk, full_size):
    """Try IMGFS decompression; return decompressed data or None."""
    if len(chunk) == full_size:
        return chunk  # stored uncompressed
    if len(chunk) == 0:
        return None
    result = xpress_decompress(chunk, full_size)
    if len(result) == full_size:
        return result
    return None
