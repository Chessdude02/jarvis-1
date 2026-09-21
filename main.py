"""JARVIS entrypoint. Run with: python main.py"""
from __future__ import annotations

import sys


def main() -> int:
    from jarvis.ui.app import main as ui_main
    return ui_main()


if __name__ == "__main__":
    sys.exit(main())
