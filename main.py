#!/usr/bin/env python3
"""LootCheck — Check your loot before you run it.

A gamer-focused file security scanner powered by VirusTotal.
"""

import sys
import os

# Ensure src is importable
if getattr(sys, 'frozen', False):
    # Running as PyInstaller bundle
    base_dir = sys._MEIPASS
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from src.app import run

if __name__ == "__main__":
    run()
