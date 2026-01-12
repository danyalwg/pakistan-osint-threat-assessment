from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .models import Article


# =============================================================================
# Storage layout (corrected + backward compatible)
# =============================================================================
#
# Legacy:
#   data/news/<COUNTRY>/<source_slug>.json
#
# Run-based (canonical):
#   data/runs/<run_id>/
#       meta.json
#       fetched/<COUNTRY>/<source_slug>.json
#       shortlisted/<COUNTRY>/<source_slug>.json
#
# Backward compatible:
#   data/runs/<run_id>/raw/  (treated as alias of fetched/)
# =============================================================================


# -----------------------
# Helpers
# -----------------------
def _safe_slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"[^a-z0-9\-_]+", "", s)
    return s or "source"


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_id_now_utc() -> str:
    # Example: run_2026-01-12_15-20-05
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    return f"run_{ts}"


def _ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


# -----------------------
# Legacy storage: data/news/<COUNTRY>/<source>.json
# -----------------------
def ensure_news_dir(base_dir: str) -> str:
    return _ensure_dir(os.path.join(base_dir, "data", "news"))


def save_articles_country_source(base_dir: str, articles: List[Article]) -> None:
    """
    Legacy save:
      data/news/<COUNTRY>/<source_slug>.json

    NOTE: For run-based saving, use save_articles_to_run_fetched/shortlisted.
    """
    news_dir = ensure_news_dir(base_dir)

    grouped: Dict[str, Dict[str, List[Article]]] = {}
    for a in articles:
        country = (a.country or "").strip() or "UNKNOWN"
        source_slug = (a.source_slug or "").strip() or _safe_slug(a.source_name)
        grouped.setdefault(country, {}).setdefault(source_slug, []).append(a)

    for country, by_source in grouped.items():
        cdir = os.path.join(news_dir, country)
        _ensure_dir(cdir)
        for source_slug, items in by_source.items():
            path = os.path.join(cdir, f"{source_slug}.json")
            payload = [x.to_dict() for x in items]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)


def load_all_articles(base_dir: str) -> List[Article]:
    """
    Legacy load:
      data/news/<COUNTRY>/*.json
    """
    news_dir = ensure_news_dir(base_dir)
    out: List[Article] = []
    if not os.path.isdir(news_dir):
        return out

    for country in os.listdir(news_dir):
        cdir = os.path.join(news_dir, country)
        if not os.path.isdir(cdir):
            continue
        for fname in os.listdir(cdir):
            if not fname.lower().endswith(".json"):
                continue
            fpath = os.path.join(cdir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for d in data:
                        try:
                            out.append(Article.from_dict(d))
                        except Exception:
                            continue
            except Exception:
                continue

    return out


# -----------------------
# Run-based storage
# -----------------------
def runs_root_dir(base_dir: str) -> str:
    return _ensure_dir(os.path.join(base_dir, "data", "runs"))


def run_dir(base_dir: str, run_id: str) -> str:
    rid = (run_id or "").strip()
    if not rid:
        raise ValueError("run_id is required")
    return _ensure_dir(os.path.join(runs_root_dir(base_dir), rid))


def ensure_run_structure(base_dir: str, run_id: str) -> Dict[str, str]:
    """
    Ensures canonical run structure exists:

      data/runs/<run_id>/
        fetched/
        shortlisted/
        meta.json

    Backward-compat:
      data/runs/<run_id>/raw/ is treated as alias of fetched/.
      We do NOT force-create raw/ anymore, but we return raw_dir as an alias
      pointing to fetched_dir so older code paths still work.
    """
    rdir = run_dir(base_dir, run_id)

    fetched_dir = _ensure_dir(os.path.join(rdir, "fetched"))
    shortlisted_dir = _ensure_dir(os.path.join(rdir, "shortlisted"))

    # Backward compatible alias:
    raw_dir_alias = fetched_dir

    return {
        "run_dir": rdir,
        "fetched_dir": fetched_dir,
        "shortlisted_dir": shortlisted_dir,
        "raw_dir": raw_dir_alias,  # alias for older code
    }


def create_new_run(base_dir: str, *, run_id: Optional[str] = None, note: str = "") -> Tuple[str, str]:
    """
    Creates a new run folder with UTC timestamp naming by default.

    Returns (run_id, run_path).
    """
    rid = (run_id or "").strip() or _run_id_now_utc()
    paths = ensure_run_structure(base_dir, rid)

    meta_path = os.path.join(paths["run_dir"], "meta.json")
    if not os.path.isfile(meta_path):
        meta = {
            "version": 2,
            "run_id": rid,
            "created_at": _iso_utc_now(),
            "note": note.strip(),
            "layout": {
                "canonical": "fetched/ + shortlisted/",
                "backward_compatible_alias": "raw/ -> fetched/",
            },
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

    return rid, paths["run_dir"]


def list_runs(base_dir: str) -> List[str]:
    """
    Returns run_ids sorted by most-recent-ish name (descending).
    (run_ids are timestamped by default).
    """
    root = runs_root_dir(base_dir)
    if not os.path.isdir(root):
        return []
    runs = [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]
    runs.sort(reverse=True)
    return runs


def get_latest_run_id(base_dir: str) -> Optional[str]:
    runs = list_runs(base_dir)
    return runs[0] if runs else None


def _save_articles_grouped(stage_dir: str, articles: List[Article]) -> None:
    """
    Saves articles grouped into:
      <stage_dir>/<COUNTRY>/<source_slug>.json
    """
    grouped: Dict[str, Dict[str, List[Article]]] = {}

    for a in articles:
        country = (a.country or "").strip() or "UNKNOWN"
        source_slug = (a.source_slug or "").strip() or _safe_slug(a.source_name)
        grouped.setdefault(country, {}).setdefault(source_slug, []).append(a)

    for country, by_source in grouped.items():
        cdir = os.path.join(stage_dir, country)
        _ensure_dir(cdir)
        for source_slug, items in by_source.items():
            path = os.path.join(cdir, f"{source_slug}.json")
            payload = [x.to_dict() for x in items]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)


def save_articles_to_run_fetched(
    base_dir: str,
    run_id: str,
    articles: List[Article],
    *,
    run_created_at: Optional[str] = None,
) -> None:
    """
    Saves FETCHED (post-extraction) articles into:
      data/runs/<run_id>/fetched/<COUNTRY>/<source_slug>.json

    Also stamps run fields on the Article objects (if missing).
    """
    paths = ensure_run_structure(base_dir, run_id)
    created_at = (run_created_at or "").strip() or _iso_utc_now()
    now = _iso_utc_now()

    for a in articles:
        if not a.run_id:
            a.run_id = run_id
        if not a.run_created_at:
            a.run_created_at = created_at
        if not a.fetched_at:
            a.fetched_at = now

    _save_articles_grouped(paths["fetched_dir"], articles)


def save_articles_to_run_raw(
    base_dir: str,
    run_id: str,
    articles: List[Article],
    *,
    run_created_at: Optional[str] = None,
) -> None:
    """
    BACKWARD COMPATIBILITY wrapper.

    Old layout used:
      data/runs/<run_id>/raw/...

    Canonical layout now uses:
      data/runs/<run_id>/fetched/...

    This function writes into fetched/ (canonical).
    """
    save_articles_to_run_fetched(base_dir, run_id, articles, run_created_at=run_created_at)


def save_articles_to_run_shortlisted(
    base_dir: str,
    run_id: str,
    shortlisted_articles: List[Article],
    *,
    run_created_at: Optional[str] = None,
) -> None:
    """
    Saves SHORTLISTED articles into:
      data/runs/<run_id>/shortlisted/<COUNTRY>/<source_slug>.json

    Also stamps run fields on the Article objects (if missing).
    """
    paths = ensure_run_structure(base_dir, run_id)
    created_at = (run_created_at or "").strip() or _iso_utc_now()

    for a in shortlisted_articles:
        if not a.run_id:
            a.run_id = run_id
        if not a.run_created_at:
            a.run_created_at = created_at

    _save_articles_grouped(paths["shortlisted_dir"], shortlisted_articles)


def load_all_articles_from_run(base_dir: str, run_id: str, which: str = "fetched") -> List[Article]:
    """
    Loads articles from a run stage:

    which="fetched":
      data/runs/<run_id>/fetched/<COUNTRY>/*.json
      (falls back to raw/ if fetched/ doesn't exist)

    which="raw":
      data/runs/<run_id>/raw/<COUNTRY>/*.json
      (falls back to fetched/ if raw/ doesn't exist)

    which="shortlisted":
      data/runs/<run_id>/shortlisted/<COUNTRY>/*.json
    """
    which_norm = (which or "fetched").strip().lower()
    if which_norm not in ("fetched", "raw", "shortlisted"):
        raise ValueError('which must be "fetched", "raw", or "shortlisted"')

    rdir = run_dir(base_dir, run_id)

    # Resolve base stage dir with fallback between fetched/raw
    if which_norm == "shortlisted":
        base_path = os.path.join(rdir, "shortlisted")
        if not os.path.isdir(base_path):
            return []
    else:
        primary = "fetched" if which_norm == "fetched" else "raw"
        fallback = "raw" if primary == "fetched" else "fetched"
        base_path = os.path.join(rdir, primary)
        if not os.path.isdir(base_path):
            base_path = os.path.join(rdir, fallback)
            if not os.path.isdir(base_path):
                return []

    out: List[Article] = []
    for country in os.listdir(base_path):
        cdir = os.path.join(base_path, country)
        if not os.path.isdir(cdir):
            continue
        for fname in os.listdir(cdir):
            if not fname.lower().endswith(".json"):
                continue
            fpath = os.path.join(cdir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for d in data:
                        try:
                            out.append(Article.from_dict(d))
                        except Exception:
                            continue
            except Exception:
                continue

    # Stamp run_id if missing (older run files or manually imported json)
    for a in out:
        if not a.run_id:
            a.run_id = run_id

    return out
