from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import List, Tuple

from .models import Article


# -----------------------
# File paths
# -----------------------
def _kw_paths(base_dir: str) -> Tuple[str, str]:
    data_dir = os.path.join(base_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    national_path = os.path.join(data_dir, "keywords_national.json")
    threat_path = os.path.join(data_dir, "keywords_threat.json")
    return national_path, threat_path


# -----------------------
# Load / Save
# -----------------------
def load_keywords_national(base_dir: str) -> List[str]:
    national_path, _ = _kw_paths(base_dir)
    if not os.path.isfile(national_path):
        return []
    with open(national_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    kws = data.get("keywords", [])
    return _clean_keywords(kws)


def load_keywords_threat(base_dir: str) -> List[str]:
    _, threat_path = _kw_paths(base_dir)
    if not os.path.isfile(threat_path):
        return []
    with open(threat_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    kws = data.get("keywords", [])
    return _clean_keywords(kws)


def save_keywords_national(base_dir: str, keywords: List[str]) -> None:
    national_path, _ = _kw_paths(base_dir)
    payload = {"version": 1, "enabled": True, "keywords": _clean_keywords(keywords)}
    with open(national_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def save_keywords_threat(base_dir: str, keywords: List[str]) -> None:
    _, threat_path = _kw_paths(base_dir)
    payload = {"version": 1, "enabled": True, "keywords": _clean_keywords(keywords)}
    with open(threat_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def ensure_default_keyword_files(base_dir: str) -> None:
    """
    If keywords jsons are missing, create minimal defaults.
    """
    national_path, threat_path = _kw_paths(base_dir)
    if not os.path.isfile(national_path):
        save_keywords_national(base_dir, ["Pakistan", "Pakistani", "Islamabad", "Karachi", "Lahore"])
    if not os.path.isfile(threat_path):
        save_keywords_threat(base_dir, ["blast", "bomb", "attack", "explosion", "terror"])


# -----------------------
# Matching (smarter than plain substring)
# -----------------------
def _clean_keywords(kws) -> List[str]:
    out: List[str] = []
    if not isinstance(kws, list):
        return out
    for k in kws:
        if isinstance(k, str):
            k2 = k.strip()
            if k2:
                out.append(k2)

    # dedupe while preserving order
    seen = set()
    uniq: List[str] = []
    for k in out:
        key = k.casefold()
        if key not in seen:
            seen.add(key)
            uniq.append(k)
    return uniq


def _normalize_text(s: str) -> str:
    s = (s or "").replace("\u00a0", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _compile_keyword_patterns(keywords: List[str]) -> List[Tuple[str, re.Pattern]]:
    """
    Creates regex patterns:
    - For alnum-only keywords -> word boundary matching
    - For phrases/symbols -> escaped substring match (case-insensitive)
    """
    patterns: List[Tuple[str, re.Pattern]] = []
    for k in _clean_keywords(keywords):
        if re.fullmatch(r"[A-Za-z0-9]+", k):
            pat = re.compile(rf"\b{re.escape(k)}\b", flags=re.IGNORECASE)
        else:
            pat = re.compile(re.escape(k), flags=re.IGNORECASE)
        patterns.append((k, pat))
    return patterns


def _match_keywords(hay: str, patterns: List[Tuple[str, re.Pattern]]) -> List[str]:
    hay = _normalize_text(hay)
    hits: List[str] = []
    for k, pat in patterns:
        if pat.search(hay):
            hits.append(k)
    return hits


def _article_haystack(a: Article) -> str:
    return " ".join(
        [
            a.title or "",
            a.summary or "",
            a.content_text or "",
            a.url or "",
            a.author or "",
        ]
    )


def _ensure_raw(a: Article) -> None:
    if a.raw is None:
        a.raw = {}


def _write_layer1_fields(a: Article, nat_hits: List[str], thr_hits: List[str], shortlisted: bool) -> None:
    """
    Ensures both the spec fields and backward compatible fields exist.

    Spec fields:
      - kw_national_hits
      - kw_threat_hits
      - shortlisted

    Backward compatible fields:
      - keywords_national_matched
      - keywords_threat_matched
      - keywords_matched (union)
      - national_relevant / threat_relevant
    """
    # Spec fields
    a.kw_national_hits = list(nat_hits)
    a.kw_threat_hits = list(thr_hits)
    a.shortlisted = bool(shortlisted)

    # Existing/legacy fields (kept consistent)
    a.keywords_national_matched = list(nat_hits)
    a.keywords_threat_matched = list(thr_hits)
    a.national_relevant = bool(nat_hits)
    a.threat_relevant = bool(thr_hits) if a.national_relevant else False

    # keywords_matched legacy union
    union = list(dict.fromkeys((a.keywords_matched or []) + nat_hits + thr_hits))
    a.keywords_matched = union

    # Also write into raw for UI compatibility across versions
    _ensure_raw(a)
    a.raw["kw_national_hits"] = list(nat_hits)
    a.raw["kw_threat_hits"] = list(thr_hits)
    a.raw["kw_shortlisted"] = bool(shortlisted)


# -----------------------
# Two-layer shortlisting
# -----------------------
@dataclass
class ShortlistResult:
    articles_all: List[Article]
    national_pass: List[Article]
    threat_pass: List[Article]
    national_total_hits: int
    threat_total_hits: int


def shortlist_articles_two_layer(
    articles: List[Article],
    national_keywords: List[str],
    threat_keywords: List[str],
) -> ShortlistResult:
    """
    LAYER 1 (FILTER):
      Article must match >=1 national keyword.

    LAYER 2 (FILTER):
      Applied only to Layer-1-passed articles.
      Article must match >=1 threat keyword.

    Spec outputs per article:
      - kw_national_hits: list[str]
      - kw_threat_hits: list[str]
      - shortlisted: bool

    Also maintains backward compatible fields used elsewhere in the app.
    """
    nat_pats = _compile_keyword_patterns(national_keywords)
    thr_pats = _compile_keyword_patterns(threat_keywords)

    national_pass: List[Article] = []
    threat_pass: List[Article] = []
    nat_hits_total = 0
    thr_hits_total = 0

    # Reset all Layer-1 and Layer-2 fields first to avoid stale values
    for a in articles:
        a.kw_national_hits = []
        a.kw_threat_hits = []
        a.keywords_national_matched = []
        a.keywords_threat_matched = []
        a.national_relevant = False
        a.threat_relevant = False
        a.shortlisted = False
        _ensure_raw(a)
        a.raw["kw_national_hits"] = []
        a.raw["kw_threat_hits"] = []
        a.raw["kw_shortlisted"] = False

    # --- Layer 1 ---
    for a in articles:
        hay = _article_haystack(a)
        nat_hits = _match_keywords(hay, nat_pats)
        nat_hits_total += len(nat_hits)

        if nat_hits:
            national_pass.append(a)

        # For now, threat hits are blank, shortlisted false
        _write_layer1_fields(a, nat_hits=nat_hits, thr_hits=[], shortlisted=False)

    # --- Layer 2 (only on national_pass) ---
    for a in national_pass:
        hay = _article_haystack(a)
        thr_hits = _match_keywords(hay, thr_pats)
        thr_hits_total += len(thr_hits)

        shortlisted = bool(len(a.kw_national_hits) > 0 and len(thr_hits) > 0)
        _write_layer1_fields(a, nat_hits=a.kw_national_hits, thr_hits=thr_hits, shortlisted=shortlisted)

        if shortlisted:
            threat_pass.append(a)

    return ShortlistResult(
        articles_all=articles,
        national_pass=national_pass,
        threat_pass=threat_pass,
        national_total_hits=nat_hits_total,
        threat_total_hits=thr_hits_total,
    )
