"""
Analyzers sub-package.
Each module exposes one public entry point: analyze_<type>(data, result).
"""

from . import image, audio, archive, text, binary, network, pdf
