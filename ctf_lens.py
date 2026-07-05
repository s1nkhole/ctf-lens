#!/usr/bin/env python3
"""
Backward-compatibility shim.
Old usage: python ctf_lens.py file.png
New usage: ctf-lens file.png  (after pip install .)
Both continue to work.
"""
import sys
import os

# Ensure the package directory is on the path when running as a script
sys.path.insert(0, os.path.dirname(__file__))

from ctf_lens.cli import main
main()
