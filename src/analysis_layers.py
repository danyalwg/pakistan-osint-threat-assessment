from __future__ import annotations
import platform
import traceback
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone, date
from typing import Callable, Dict, List, Optional, Tuple

from .models import Article


# =============================================================================
# Utilities
# =============================================================================
def _safe_text(s: Optional[str]) -> str:
    return (s or "").replace("\u00a0", " ").strip()


def _normalize_ws(s: str) -> str:
    return re.sub(r"\s+", " ", _safe_text(s)).strip()


def _haystack(a: Article) -> str:
    return _normalize_ws(
        " ".join(
            [
                a.title or "",
                a.summary or "",
                a.content_text or "",
                a.url or "",
                a.author or "",
            ]
        )
    )


def _try_parse_iso_date(s: Optional[str]) -> Optional[date]:
    if not s:
        return None
    t = s.strip()
    if not t:
        return None
    # YYYY-MM-DD
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", t)
    if m:
        try:
            return datetime.strptime(t, "%Y-%m-%d").date()
        except Exception:
            return None
    # ISO datetime, allow Z
    try:
        dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
        return dt.date()
    except Exception:
        pass
    # Try prefix YYYY-MM-DD
    m2 = re.match(r"^(\d{4}-\d{2}-\d{2})", t)
    if m2:
        try:
            return datetime.strptime(m2.group(1), "%Y-%m-%d").date()
        except Exception:
            return None
    return None


def _today_utc() -> date:
    return datetime.now(timezone.utc).date()


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _prepriority_bucket(v: Optional[float]) -> str:
    if v is None:
        return "LOW"
    try:
        x = float(v)
    except Exception:
        return "LOW"
    if x >= 80:
        return "CRITICAL"
    if x >= 60:
        return "HIGH"
    if x >= 40:
        return "MEDIUM"
    return "LOW"


# =============================================================================
# LAYER 2: Relevance + Evidence + Urgency + Keyword Intensity + PrePriority
# =============================================================================

# Pakistan signal heuristics for L:
# "Pakistan location or Pakistan security entity mentioned"
# We do NOT depend on a tagged keyword taxonomy, we use pragmatic patterns.
_PAK_LOCATION_PAT = re.compile(
    r"\b(Islamabad|Rawalpindi|Karachi|Lahore|Peshawar|Quetta|Multan|Faisalabad|Gwadar|"
    r"Gilgit|Skardu|Muzaffarabad|Mirpur|Kashmir|Balochistan|Sindh|Punjab|Khyber\s+Pakhtunkhwa|"
    r"KP|GB|AJK|FATA)\b",
    flags=re.IGNORECASE,
)
_PAK_SECURITY_PAT = re.compile(
    r"\b(Pakistan\s+Army|Pak\s+Army|PAF|Pakistan\s+Air\s+Force|Pakistan\s+Navy|ISI|ISPR|DG\s+ISPR|"
    r"FIA|IB\b|Intelligence\s+Bureau|CTD|Counter\s+Terrorism\s+Department|Rangers|Frontier\s+Corps|FC\b|"
    r"NADRA|Police|Sindh\s+Police|Punjab\s+Police|KPK\s+Police|Balochistan\s+Police)\b",
    flags=re.IGNORECASE,
)

# Evidence heuristics
_QUOTE_ATTRIB_PAT = re.compile(
    r"(\bsaid\b|\bstated\b|\btold\b|\baccording to\b|\badded\b)\s+[^.]{0,80}",
    flags=re.IGNORECASE,
)
_CITATION_PAT = re.compile(
    r"\b(report|statement|press\s+release|briefing|dossier|white\s+paper|document|UN|United\s+Nations|"
    r"FATF|IMF|World\s+Bank|court|police\s+report|investigation)\b",
    flags=re.IGNORECASE,
)
_NUMERIC_PAT = re.compile(r"(\b\d{1,4}\b|\b\d{1,3}(?:,\d{3})+\b)", flags=re.IGNORECASE)

# Named official / organization heuristic: titles and org suffixes
_NAMED_ENTITY_PAT = re.compile(
    r"\b(Prime\s+Minister|President|Chief\s+Minister|Interior\s+Minister|Foreign\s+Minister|"
    r"Army\s+Chief|COAS|DG\s+ISPR|spokesperson|commissioner|inspector|IG|DIG|"
    r"Ministry|Ministries|Department|Court|High\s+Court|Supreme\s+Court|Parliament|Senate|"
    r"Assembly|Police|Rangers|Army|Navy|Air\s+Force|FIA|NADRA|ISPR|UN|IMF|FATF|World\s+Bank)\b",
    flags=re.IGNORECASE,
)


def _count_explicit_pakistan_mentions(text: str) -> int:
    # Explicit "Pakistan" mentions only (not PK/Pak etc.)
    return len(re.findall(r"\bPakistan\b", text, flags=re.IGNORECASE))


def _compute_relevance(a: Article) -> float:
    kw_nat = list(a.kw_national_hits or []) or list(a.keywords_national_matched or [])
    N = min(len(kw_nat), 10)

    hay = _haystack(a)
    P = min(_count_explicit_pakistan_mentions(hay), 5)

    L = 1 if (_PAK_LOCATION_PAT.search(hay) or _PAK_SECURITY_PAT.search(hay)) else 0

    # Source country boost
    S = 10 if (a.country or "").strip().upper() == "PAKISTAN" else 0

    R = min(100.0, 10.0 * N + 8.0 * P + 25.0 * float(L) + float(S))
    return float(R)


def _evidence_points(a: Article) -> int:
    hay = _haystack(a)
    pts = 0

    # +2 named official or organization
    if _NAMED_ENTITY_PAT.search(hay):
        pts += 2

    # +2 numeric data present (casualties, dates, counts)
    if _NUMERIC_PAT.search(hay):
        pts += 2

    # +2 specific location mentioned
    if _PAK_LOCATION_PAT.search(hay) or re.search(r"\b(city|district|province|village|tehsil)\b", hay, re.IGNORECASE):
        pts += 2

    # +2 cited report/document/statement
    if _CITATION_PAT.search(hay):
        pts += 2

    # +2 direct quote with speaker attribution
    # Heuristic: presence of quotes plus attribution language nearby
    if ('"' in hay or "“" in hay or "’" in hay or "”" in hay) and _QUOTE_ATTRIB_PAT.search(hay):
        pts += 2

    return int(_clamp(float(pts), 0.0, 10.0))


def _evidence_bucket_and_numeric(points: int) -> Tuple[str, float]:
    if points <= 3:
        return "LOW", 25.0
    if points <= 7:
        return "MED", 60.0
    return "HIGH", 90.0


def _compute_urgency(a: Article) -> float:
    """
    Urgency heuristic based on recency and threat-ish keyword hits.
    """
    today = _today_utc()
    pub = _try_parse_iso_date(a.published_at)
    age_days = 999
    if pub:
        age_days = abs((today - pub).days)

    # Recency score: 0..60
    if age_days <= 0:
        rec = 60.0
    elif age_days <= 1:
        rec = 55.0
    elif age_days <= 2:
        rec = 50.0
    elif age_days <= 3:
        rec = 45.0
    elif age_days <= 7:
        rec = 35.0
    elif age_days <= 14:
        rec = 25.0
    elif age_days <= 30:
        rec = 15.0
    else:
        rec = 5.0

    # Threat keyword boost: 0..40
    kw_thr = list(a.kw_threat_hits or []) or list(a.keywords_threat_matched or [])
    thr = min(len(kw_thr), 10)
    thr_boost = float(thr) * 4.0  # up to 40

    return float(_clamp(rec + thr_boost, 0.0, 100.0))


def _compute_keyword_intensity(a: Article) -> float:
    """
    Keyword intensity is how saturated the article is with hits.
    """
    kw_nat = list(a.kw_national_hits or []) or list(a.keywords_national_matched or [])
    kw_thr = list(a.kw_threat_hits or []) or list(a.keywords_threat_matched or [])
    total = len(kw_nat) + len(kw_thr)
    return float(_clamp(10.0 * float(min(total, 10)), 0.0, 100.0))


def compute_layer2_scores(articles: List[Article]) -> None:
    """
    Mutates articles with Layer 2 scores:
      - relevance_score
      - evidence_strength, evidence_numeric
      - urgency_score
      - keyword_intensity
      - prepriority_score, prepriority_bucket
    """
    for a in articles:
        R = _compute_relevance(a)
        pts = _evidence_points(a)
        E_bucket, E_num = _evidence_bucket_and_numeric(pts)
        U = _compute_urgency(a)
        K = _compute_keyword_intensity(a)

        # PrePriority weights (heuristic)
        # Pre = 0.45*R + 0.25*U + 0.20*E + 0.10*K
        Pre = 0.45 * R + 0.25 * U + 0.20 * E_num + 0.10 * K

        a.relevance_score = float(_clamp(R, 0.0, 100.0))
        a.evidence_strength = E_bucket
        a.evidence_numeric = float(E_num)
        a.urgency_score = float(_clamp(U, 0.0, 100.0))
        a.keyword_intensity = float(_clamp(K, 0.0, 100.0))
        a.prepriority_score = float(_clamp(Pre, 0.0, 100.0))
        a.prepriority_bucket = _prepriority_bucket(a.prepriority_score)


# =============================================================================
# Select articles for LLM (Layer 3) based on Layer 2 PrePriority
# =============================================================================
def select_articles_for_llm(
    articles: List[Article],
    *,
    mode: str = "top_n",
    top_n: int = 25,
    threshold: float = 60.0,
) -> List[Article]:
    """
    Returns subset of articles to run through Layer 3 LLM scoring.

    mode:
      - "top_n": take top N by prepriority_score
      - "threshold": take all with prepriority_score >= threshold
    """
    items = list(articles)

    # Ensure Layer 2 computed
    for a in items:
        if a.prepriority_score is None:
            compute_layer2_scores([a])

    items.sort(key=lambda x: float(x.prepriority_score or 0.0), reverse=True)

    if mode == "threshold":
        return [x for x in items if float(x.prepriority_score or 0.0) >= float(threshold)]

    # default: top_n
    return items[: max(0, int(top_n))]


# =============================================================================
# LAYER 3: LLM scoring
# =============================================================================
def _coerce_float(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return float(default)


def _threat_level_from_score(t: float) -> str:
    t = float(t)
    if t >= 75:
        return "CRITICAL"
    if t >= 50:
        return "HIGH"
    if t >= 25:
        return "MED"
    return "LOW"


def _clean_vector(v: str) -> str:
    v = (v or "").strip().upper()
    allowed = {"MILITARY", "TERROR", "CYBER", "DIPLO", "ECON", "INTERNAL", "OTHER"}
    return v if v in allowed else "OTHER"


def _extract_json_object(text: str) -> Optional[dict]:
    """
    Attempts to pull the first JSON object from an LLM completion.
    """
    if not text:
        return None
    t = text.strip()

    # Quick path if whole thing is JSON
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    # Find first {...} block
    m = re.search(r"\{[\s\S]*\}", t)
    if not m:
        return None

    blob = m.group(0)
    try:
        obj = json.loads(blob)
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def _build_llm_prompt(a: Article) -> str:
    """
    Forces JSON-only output.
    """
    title = _safe_text(a.title)
    published = _safe_text(a.published_at)
    source = _safe_text(a.source_name)
    country = _safe_text(a.country)
    url = _safe_text(a.url)
    text = _safe_text(a.content_text or a.summary or "")

    # Limit text to reduce token load (still not token-safe, kept for backward compatibility)
    text = text[:6000]

    spec = {
        "threat_score": "number 0-100",
        "threat_level": "LOW|MED|HIGH|CRITICAL (must match score thresholds)",
        "threat_vector": "MILITARY|TERROR|CYBER|DIPLO|ECON|INTERNAL|OTHER",
        "one_liner_threat": "one sentence",
        "reasons": "2-4 short bullet strings",
    }

    return (
        "You are an OSINT threat analyst for Pakistan.\n"
        "Task: Evaluate the threat severity of the article for Pakistan.\n"
        "Output MUST be a single valid JSON object and nothing else.\n"
        "Schema:\n"
        f"{json.dumps(spec, ensure_ascii=False)}\n\n"
        "Threat score thresholds:\n"
        "0-24 LOW, 25-49 MED, 50-74 HIGH, 75-100 CRITICAL.\n\n"
        "Article:\n"
        f"Title: {title}\n"
        f"Published: {published}\n"
        f"Source: {source}\n"
        f"SourceCountry: {country}\n"
        f"URL: {url}\n"
        f"Text:\n{text}\n\n"
        "Now output the JSON object."
    )


def _sanitize_for_llm(s: str) -> str:
    # Remove embedded NULs and normalize line endings for native backends.
    s = (s or "").replace("\x00", "")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return s


def _build_llm_prompt_with_budget(a: Article, llm, *, max_prompt_tokens: int) -> str:
    """Build the LLM prompt while enforcing a token budget."""
    title = _sanitize_for_llm(_safe_text(a.title))
    published = _sanitize_for_llm(_safe_text(a.published_at))
    source = _sanitize_for_llm(_safe_text(a.source_name))
    country = _sanitize_for_llm(_safe_text(a.country))
    url = _sanitize_for_llm(_safe_text(a.url))

    spec = {
        "threat_score": "number 0-100",
        "threat_level": "LOW|MED|HIGH|CRITICAL (must match score thresholds)",
        "threat_vector": "MILITARY|TERROR|CYBER|DIPLO|ECON|INTERNAL|OTHER",
        "one_liner_threat": "one sentence",
        "reasons": "2-4 short bullet strings",
    }

    header = (
        "You are an OSINT threat analyst for Pakistan.\n"
        "Task: Evaluate the threat severity of the article for Pakistan.\n"
        "Output MUST be a single valid JSON object and nothing else.\n"
        "Schema:\n"
        f"{json.dumps(spec, ensure_ascii=False)}\n\n"
        "Threat score thresholds:\n"
        "0-24 LOW, 25-49 MED, 50-74 HIGH, 75-100 CRITICAL.\n\n"
        "Article:\n"
        f"Title: {title}\n"
        f"Published: {published}\n"
        f"Source: {source}\n"
        f"SourceCountry: {country}\n"
        f"URL: {url}\n"
        "Text:\n"
    )
    footer = "\n\nNow output the JSON object."

    full_text = _sanitize_for_llm(_safe_text(a.content_text or a.summary or ""))

    # Start with a conservative slice, then shrink if needed.
    text_slice = full_text[:6000]

    def tok_count(p: str) -> int:
        try:
            return len(llm.tokenize(p.encode("utf-8", errors="ignore")))
        except Exception:
            # Fallback estimate if tokenize is unavailable for any reason.
            return max(1, len(p) // 3)

    while True:
        prompt = header + text_slice + footer
        if tok_count(prompt) <= max_prompt_tokens:
            return prompt

        if len(text_slice) <= 900:
            tiny = text_slice[:900].rstrip() + " ...[TRUNCATED]"
            return header + tiny + footer

        text_slice = text_slice[: int(len(text_slice) * 0.75)]


def _load_llama(model_path: str, progress_cb: Optional[Callable[[str], None]] = None):
    def log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    log("[LLM][DBG] Enter _load_llama()")
    log(f"[LLM][DBG] model_path={model_path!r}")
    log(f"[LLM][DBG] os.getcwd()={os.getcwd()!r}")
    log(f"[LLM][DBG] platform={platform.platform()}")
    log(f"[LLM][DBG] python={platform.python_version()} ({platform.python_implementation()})")
    log(f"[LLM][DBG] machine={platform.machine()} processor={platform.processor()}")
    log(f"[LLM][DBG] pid={os.getpid()}")

    if not model_path or not os.path.isfile(model_path):
        raise RuntimeError(f"Model file not found: {model_path}")

    try:
        size_bytes = os.path.getsize(model_path)
        log(f"[LLM][DBG] model_size_bytes={size_bytes}")
        log(f"[LLM][DBG] model_size_gb={size_bytes / 1024 / 1024 / 1024:.2f}")
    except Exception as ex:
        log(f"[LLM][DBG] getsize failed: {type(ex).__name__}: {ex}")

    # Import llama_cpp and log where it comes from
    log("[LLM][DBG] Importing llama_cpp...")
    try:
        import llama_cpp  # type: ignore
        log(f"[LLM][DBG] llama_cpp imported from: {getattr(llama_cpp, '__file__', 'UNKNOWN')}")
        log(f"[LLM][DBG] llama_cpp version: {getattr(llama_cpp, '__version__', 'UNKNOWN')}")
        from llama_cpp import Llama  # type: ignore
        log("[LLM][DBG] from llama_cpp import Llama OK")
    except Exception as ex:
        tb = traceback.format_exc()
        log(f"[LLM][DBG] llama_cpp import failed: {type(ex).__name__}: {ex}")
        log(tb)
        raise

    threads = max(1, min(8, os.cpu_count() or 4))
    log(f"[LLM][DBG] os.cpu_count()={os.cpu_count()} threads={threads}")

    # Use the most conservative init that matches your working smoke test.
    params = {
        "model_path": model_path,
        "n_ctx": 1024,
        "n_threads": threads,
        "n_gpu_layers": 0,
        "use_mmap": True,
        "use_mlock": False,
        "n_batch": 16,
        "verbose": False,
    }
    log(f"[LLM][DBG] Llama init params: {json.dumps(params, ensure_ascii=False)}")
    log("[LLM][DBG] About to call Llama(...) constructor")

    # This is where the native crash happens if it happens at init.
    llm = Llama(**params)

    log("[LLM][DBG] Llama(...) constructed successfully")
    return llm




def run_layer3_llm_scoring(
    articles: List[Article],
    model_path: str,
    *,
    progress_cb: Optional[Callable[[str], None]] = None,
) -> None:
    """
    Runs LLM scoring in-place on the given list of articles.
    """
    model_path = (model_path or "").strip()
    if not model_path or not os.path.isfile(model_path):
        raise RuntimeError(f"Model file not found: {model_path}")

    if progress_cb:
        progress_cb("[LLM] Loading model...")

    llm = _load_llama(model_path, progress_cb=progress_cb)

    if progress_cb:
        progress_cb("[LLM] Loading model...")

    try:
        llm = _load_llama(model_path, progress_cb=progress_cb)
    except Exception as ex:
        if progress_cb:
            progress_cb(f"[LLM][DBG] Model load exception: {type(ex).__name__}: {ex}")
            progress_cb(traceback.format_exc())
        raise

    if progress_cb:
        progress_cb("[LLM] Model loaded OK.")



    # Leave headroom for generation and internal overhead.
    # With n_ctx=4096, 3200 prompt tokens is a safe default.
    max_prompt_tokens = 3200

    for idx, a in enumerate(articles, start=1):
        if progress_cb:
            progress_cb(f"LLM scoring {idx}/{len(articles)}")

        try:
            prompt = _build_llm_prompt_with_budget(a, llm, max_prompt_tokens=max_prompt_tokens)

            out = llm(
                prompt,
                max_tokens=128,
                temperature=0.2,
                top_p=0.9,
                stop=["\n\n\n"],
            )
        except OSError as ex:
            # Native backend crash surfaced as OSError on Windows (access violation).
            a.threat_score = float(a.threat_score or 0.0)
            a.threat_level = a.threat_level or _threat_level_from_score(float(a.threat_score or 0.0))
            a.threat_vector = a.threat_vector or "OTHER"
            a.one_liner_threat = a.one_liner_threat or ""
            if not a.reasons:
                a.reasons = []
            a.extraction_notes.append(f"LLM_ERROR: {type(ex).__name__}: {ex}")
            continue
        except Exception as ex:
            a.threat_score = float(a.threat_score or 0.0)
            a.threat_level = a.threat_level or _threat_level_from_score(float(a.threat_score or 0.0))
            a.threat_vector = a.threat_vector or "OTHER"
            a.one_liner_threat = a.one_liner_threat or ""
            if not a.reasons:
                a.reasons = []
            a.extraction_notes.append(f"LLM_ERROR: {type(ex).__name__}: {ex}")
            continue

        text = ""
        try:
            text = out["choices"][0]["text"]
        except Exception:
            text = str(out)

        obj = _extract_json_object(text)
        if not obj:
            a.threat_score = a.threat_score if a.threat_score is not None else 0.0
            a.threat_level = a.threat_level or _threat_level_from_score(float(a.threat_score or 0.0))
            a.threat_vector = a.threat_vector or "OTHER"
            a.one_liner_threat = a.one_liner_threat or ""
            if not a.reasons:
                a.reasons = []
            a.extraction_notes.append("LLM_PARSE_ERROR: could not extract JSON")
            continue

        t = _clamp(_coerce_float(obj.get("threat_score", 0.0), 0.0), 0.0, 100.0)

        vec = _clean_vector(str(obj.get("threat_vector", "") or "OTHER"))
        one = _safe_text(obj.get("one_liner_threat", "") or "")
        rs = obj.get("reasons", [])
        if not isinstance(rs, list):
            rs = []
        reasons = [str(x).strip() for x in rs if str(x).strip()][:6]
        if len(reasons) > 4:
            reasons = reasons[:4]

        a.threat_score = float(t)
        a.threat_level = _threat_level_from_score(float(t))
        a.threat_vector = vec
        a.one_liner_threat = one
        a.reasons = reasons


# =============================================================================
# FINAL RISK INDEX
# =============================================================================
def compute_risk_index(articles: List[Article]) -> None:
    """
    RiskIndex = 0.45*T + 0.35*R + 0.10*U + 0.10*E
    """
    for a in articles:
        T = float(a.threat_score or 0.0)
        R = float(a.relevance_score or 0.0)
        U = float(a.urgency_score or 20.0)
        E = float(a.evidence_numeric or 25.0)

        risk = 0.45 * T + 0.35 * R + 0.10 * U + 0.10 * E
        a.risk_index = float(_clamp(risk, 0.0, 100.0))


# =============================================================================
# Legacy stubs retained for compatibility (optional)
# =============================================================================
def run_truth_layer_stub(articles: List[Article]) -> List[Article]:
    for a in articles:
        a.truth_score = a.truth_score
        a.truth_label = a.truth_label
    return articles


def run_threat_layer_stub(articles: List[Article]) -> List[Article]:
    for a in articles:
        a.threat_score = a.threat_score
        a.threat_level = a.threat_level
    return articles
