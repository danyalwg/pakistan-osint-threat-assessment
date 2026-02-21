#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys


APP_NAME = "AI-based Threat Assessment of Pakistan"


def _init_llama_backend_once() -> None:
    """
    CRITICAL on Windows:
    Initialize llama-cpp backend before importing PyQt6 (Qt loads native DLLs).
    This avoids access-violation crashes caused by DLL load-order conflicts.
    """
    try:
        import llama_cpp  # type: ignore

        # Some versions crash here if the wheel/build is broken or DLL order is bad.
        llama_cpp.llama_backend_init()
        print("[BOOT] llama backend initialized (pre-Qt).")
    except Exception as ex:
        # Do not hard-fail: GUI can still run; LLM will fail later if backend is broken.
        print(
            f"[BOOT] llama backend init skipped/failed: {type(ex).__name__}: {ex}",
            file=sys.stderr,
        )


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

    # IMPORTANT: do this before importing PyQt6
    _init_llama_backend_once()

    # Import project modules only after llama init attempt
    from src.sources_repo import ensure_default_data_files
    ensure_default_data_files(base_dir)

    # Import PyQt6 only after llama init attempt (prevents DLL-order issues)
    from PyQt6.QtWidgets import QApplication
    from src.gui import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)

    win = MainWindow(base_dir=base_dir)
    win.resize(1400, 850)
    win.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
