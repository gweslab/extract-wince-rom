"""Windows CE / Windows Mobile ROM image extractor.

Public entry point:
    from winmob_extract import extract_image
"""

from .extract import extract_image

__all__ = ['extract_image']
