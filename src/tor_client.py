from __future__ import annotations

import os
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import requests

try:
    from stem.process import launch_tor_with_config  # type: ignore
    HAS_STEM = True
except Exception:
    launch_tor_with_config = None  # type: ignore
    HAS_STEM = False


# -----------------------
# Helpers
# -----------------------
def _can_connect(host: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _find_free_port(host: str = "127.0.0.1") -> int:
    # Bind to port 0 to let OS choose a free port, then close.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _default_tor_exe_candidates(app_base_dir: Optional[str] = None) -> list[str]:
    """
    Try common locations without relying on GUI:
    - env TOR_EXE
    - ./data/tor/tor.exe, ./data/tor.exe relative to app_base_dir or cwd
    """
    cands: list[str] = []
    env = os.environ.get("TOR_EXE", "").strip()
    if env:
        cands.append(env)

    roots = []
    if app_base_dir:
        roots.append(app_base_dir)
    roots.append(os.getcwd())

    for root in roots:
        cands.append(os.path.join(root, "data", "tor", "tor.exe"))
        cands.append(os.path.join(root, "data", "tor.exe"))
        cands.append(os.path.join(root, "tor.exe"))

    # dedupe while preserving order
    out: list[str] = []
    seen = set()
    for p in cands:
        p2 = os.path.normpath(p)
        if p2 not in seen:
            seen.add(p2)
            out.append(p2)
    return out


def _resolve_tor_exe(app_base_dir: Optional[str]) -> Optional[str]:
    for p in _default_tor_exe_candidates(app_base_dir):
        if p and os.path.isfile(p):
            return p
    return None


# -----------------------
# Data structures
# -----------------------
@dataclass
class TorConfig:
    enabled: bool = True
    socks_proxy: str = "socks5h://127.0.0.1:9050"
    socks_port: int = 9050

    start_tor: bool = False
    tor_exe: Optional[str] = None
    data_dir: Optional[str] = None


class TorManager:
    def __init__(self, cfg: TorConfig) -> None:
        self.cfg = cfg
        self._proc = None

    def start(self) -> None:
        if not self.cfg.start_tor:
            return

        if not self.cfg.tor_exe:
            raise RuntimeError("Tor auto-start requested but tor_exe is not set.")
        if not os.path.isfile(self.cfg.tor_exe):
            raise RuntimeError(f"tor.exe not found at: {self.cfg.tor_exe}")

        data_dir = self.cfg.data_dir or os.path.join(os.getcwd(), "tor_data")
        os.makedirs(data_dir, exist_ok=True)

        # Try stem first
        if HAS_STEM and launch_tor_with_config is not None:
            self._proc = launch_tor_with_config(
                config={
                    "SocksPort": str(self.cfg.socks_port),
                    "DataDirectory": data_dir,
                    "Log": "notice stdout",
                },
                tor_cmd=self.cfg.tor_exe,
                init_msg_handler=lambda line: None,
            )
            # stem returns when tor is up
            return

        # Fallback: run tor.exe directly with torrc
        torrc_path = os.path.join(data_dir, "torrc")
        with open(torrc_path, "w", encoding="utf-8") as f:
            f.write(f"SocksPort {self.cfg.socks_port}\n")
            f.write(f"DataDirectory {data_dir}\n")
            f.write("Log notice stdout\n")

        self._proc = subprocess.Popen(
            [self.cfg.tor_exe, "-f", torrc_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )

        # Wait until Tor is bootstrapped
        deadline = time.time() + 60
        if self._proc.stdout:
            while time.time() < deadline:
                line = self._proc.stdout.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                if "Bootstrapped 100%" in line:
                    return

        raise RuntimeError("Tor started but did not bootstrap in time.")

    def stop(self) -> None:
        if not self.cfg.start_tor:
            return
        if self._proc is None:
            return
        try:
            self._proc.terminate()
        except Exception:
            pass


class TorHTTPClient:
    def __init__(self, cfg: TorConfig) -> None:
        self.cfg = cfg
        self.tor_mgr = TorManager(cfg)
        self.session = requests.Session()

        # realistic UA to reduce blocks
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/122.0.0.0 Safari/537.36"
        })

        if self.cfg.enabled:
            self.session.proxies.update({"http": self.cfg.socks_proxy, "https": self.cfg.socks_proxy})

    def start(self) -> "TorHTTPClient":
        if self.cfg.enabled and self.cfg.start_tor:
            self.tor_mgr.start()
        return self

    def close(self) -> None:
        try:
            self.session.close()
        finally:
            self.tor_mgr.stop()


# -----------------------
# NEW: managed Tor session (always Tor, self-managed)
# -----------------------
def get_managed_tor_session(
    app_base_dir: Optional[str] = None,
    prefer_ports: Tuple[int, int] = (9050, 9150),
    tor_data_dir: Optional[str] = None,
) -> TorHTTPClient:
    """
    Always returns a Tor-proxied session.
    - If Tor already running on 9050/9150 -> use it (do not start).
    - Else -> start tor.exe on an available port (try 9050, else 9150, else random free port).
    GUI is not involved.
    """
    host = "127.0.0.1"

    # 1) If Tor already running, use it
    for p in prefer_ports:
        if _can_connect(host, p):
            proxy = f"socks5h://{host}:{p}"
            cfg = TorConfig(
                enabled=True,
                socks_proxy=proxy,
                socks_port=p,
                start_tor=False,
                tor_exe=None,
                data_dir=tor_data_dir,
            )
            return TorHTTPClient(cfg).start()

    # 2) Need to start Tor
    tor_exe = _resolve_tor_exe(app_base_dir)
    if not tor_exe:
        raise RuntimeError(
            "Tor is not running and tor.exe could not be found. "
            "Set TOR_EXE env var or place tor.exe in ./data/tor/tor.exe (or ./data/tor.exe)."
        )

    # Pick a port: try 9050, then 9150, else choose free port
    chosen = None
    for p in prefer_ports:
        # If port is free (can't connect, and also not bound by something else)
        # We'll just attempt start; if it fails due to bind we fallback.
        chosen = p
        try:
            proxy = f"socks5h://{host}:{p}"
            cfg = TorConfig(
                enabled=True,
                socks_proxy=proxy,
                socks_port=p,
                start_tor=True,
                tor_exe=tor_exe,
                data_dir=tor_data_dir,
            )
            client = TorHTTPClient(cfg).start()
            # Confirm listener
            if _can_connect(host, p, timeout=0.8):
                return client
            client.close()
        except Exception:
            # try next port
            continue

    # Final fallback: random free port
    p = _find_free_port(host)
    proxy = f"socks5h://{host}:{p}"
    cfg = TorConfig(
        enabled=True,
        socks_proxy=proxy,
        socks_port=p,
        start_tor=True,
        tor_exe=tor_exe,
        data_dir=tor_data_dir,
    )
    client = TorHTTPClient(cfg).start()
    if not _can_connect(host, p, timeout=0.8):
        client.close()
        raise RuntimeError("Tor failed to start (no SOCKS listener detected).")
    return client
