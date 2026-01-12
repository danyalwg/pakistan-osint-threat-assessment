#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys

from PyQt6.QtWidgets import QApplication

from src.gui import MainWindow
from src.sources_repo import ensure_default_data_files


APP_NAME = "AI-based Threat Assessment of Pakistan"


def _resolve_base_dir(cli_base_dir: str | None) -> str:
    """
    Base directory is the project root where /data lives.

    Priority:
      1) --base-dir (if provided)
      2) directory of this main.py file
    """
    if cli_base_dir:
        return os.path.abspath(cli_base_dir)
    return os.path.dirname(os.path.abspath(__file__))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="threat-assessment-gui")
    parser.add_argument(
        "--base-dir",
        default=None,
        help="Project base directory (must contain /data). Defaults to folder containing main.py.",
    )
    args = parser.parse_args(argv)

    base_dir = _resolve_base_dir(args.base_dir)

    # Ensure required files/folders exist: data/sources.json, data/keywords.json (legacy), data/news/
    # (Your new GUI uses keywords_national.json / keywords_threat.json too, created inside gui.py.)
    ensure_default_data_files(base_dir)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)

    win = MainWindow(base_dir=base_dir)
    win.resize(1400, 850)
    win.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
