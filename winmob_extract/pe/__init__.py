"""PE32 reconstruction from CE e32_rom / o32_rom headers.

Two entry points:
    reconstruct_pe_xip(flat, base_off, e32_va, o32_va, ...)
    reconstruct_pe_imgfs(header_data, section_data_map)

Both return the PE file bytes, or None on failure.
"""

from .reconstruct import reconstruct_pe_xip, reconstruct_pe_imgfs

__all__ = ['reconstruct_pe_xip', 'reconstruct_pe_imgfs']
