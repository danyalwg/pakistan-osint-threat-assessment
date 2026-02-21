from __future__ import annotations

import json
import random
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import trafilatura


# -----------------------
# Robust fetch config
# -----------------------
RETRIES = 3
TIMEOUT_DEFAULT = 30
BACKOFF_BASE = 1.7
MAX_FETCH_BYTES = 3_000_000

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

try:
    from curl_cffi import requests as curl_requests  # type: ignore
    HAS_CURL_CFFI = True
except Exception:
    curl_requests = None  # type: ignore
    HAS_CURL_CFFI = False


# -----------------------
# Fetch primitives
# -----------------------
def _rand_headers(url: str) -> Dict[str, str]:
    """
    Browser-like headers.
    IMPORTANT: Accept-Encoding=identity helps avoid compressed junk in raw stream.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    referer = f"{parsed.scheme}://{host}/" if host else ""

    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Connection": "keep-alive",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Referer": referer,
    }


@dataclass
class FetchOutcome:
    ok: bool
    status: Optional[int] = None
    final_url: Optional[str] = None
    error: Optional[str] = None
    method: str = "requests"  # requests / requests_insecure_tls / curl_cffi
    content_type: str = ""
    content_encoding: str = ""


_TEXTLIKE_CT_RE = re.compile(
    r"(text/|application/(xml|rss\+xml|atom\+xml|xhtml\+xml|json))",
    re.I,
)


def _content_type_is_textlike(content_type: str) -> bool:
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if not ct:
        return True
    return bool(_TEXTLIKE_CT_RE.search(ct))


def _looks_binary(raw: bytes) -> bool:
    if not raw:
        return True
    if b"\x00" in raw[:2000]:
        return True
    sample = raw[:4000]
    printable = 0
    for b in sample:
        if b in (9, 10, 13):
            printable += 1
        elif 32 <= b <= 126:
            printable += 1
        elif b >= 0xC0:
            printable += 1
    ratio = printable / max(1, len(sample))
    return ratio < 0.55


def _decode_html_bytes(raw: bytes, content_type: str) -> str:
    enc = ""
    m = re.search(r"charset=([A-Za-z0-9_\-]+)", content_type or "", re.I)
    if m:
        enc = m.group(1).strip()

    if enc:
        try:
            return raw.decode(enc, errors="replace")
        except Exception:
            pass

    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return raw.decode("latin-1", errors="replace")


def _sniff_text(s: str, n: int = 260) -> str:
    s = (s or "").replace("\r", " ").replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n]


def _looks_like_block_page(html: str) -> bool:
    """
    IMPORTANT CHANGE:
    This is now only a *hint*. We do NOT stop extraction based on it.
    """
    h = (html or "").lower()
    if not h:
        return False
    signals = [
        "just a moment",
        "attention required",
        "cf-browser-verification",
        "verify you are human",
        "enable javascript and cookies",
        "captcha",
        "access denied",
    ]
    return any(x in h for x in signals)


def _fetch_html(session, url: str, timeout: int) -> Tuple[FetchOutcome, Optional[str]]:
    last_err: Optional[str] = None
    insecure_tls_used = False

    for attempt in range(1, RETRIES + 1):
        try:
            headers = _rand_headers(url)
            r = session.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )
            status = r.status_code
            ctype = (r.headers.get("Content-Type") or "").strip()
            cenc = (r.headers.get("Content-Encoding") or "").strip()
            final_url = getattr(r, "url", url)

            if status in (403, 429) and HAS_CURL_CFFI and curl_requests is not None:
                try:
                    rr = curl_requests.get(
                        url,
                        headers=headers,
                        timeout=timeout,
                        allow_redirects=True,
                        impersonate="chrome",
                        proxies=session.proxies if getattr(session, "proxies", None) else None,
                    )
                    ctype2 = (rr.headers.get("Content-Type") or "").strip()
                    cenc2 = (rr.headers.get("Content-Encoding") or "").strip()
                    raw2 = rr.content[:MAX_FETCH_BYTES]

                    if not _content_type_is_textlike(ctype2) and _looks_binary(raw2):
                        return (
                            FetchOutcome(
                                ok=False,
                                status=rr.status_code,
                                final_url=str(getattr(rr, "url", url)),
                                method="curl_cffi",
                                content_type=ctype2,
                                content_encoding=cenc2,
                                error=f"non-text response: Content-Type={ctype2}",
                            ),
                            None,
                        )

                    html2 = _decode_html_bytes(raw2, ctype2)
                    if 200 <= rr.status_code < 400 and html2:
                        return (
                            FetchOutcome(
                                ok=True,
                                status=rr.status_code,
                                final_url=str(getattr(rr, "url", url)),
                                method="curl_cffi",
                                content_type=ctype2,
                                content_encoding=cenc2,
                            ),
                            html2,
                        )
                    last_err = f"curl_cffi HTTP {rr.status_code}"
                except Exception as ex2:
                    last_err = f"curl_cffi failed: {type(ex2).__name__}: {ex2}"

            if not (200 <= status < 400):
                last_err = f"HTTP {status}"
                raise RuntimeError(last_err)

            # CRITICAL FIX: decode compressed payload when reading raw
            if getattr(r, "raw", None) is not None:
                try:
                    r.raw.decode_content = True  # type: ignore[attr-defined]
                except Exception:
                    pass

            raw = r.raw.read(MAX_FETCH_BYTES) if getattr(r, "raw", None) else (r.content[:MAX_FETCH_BYTES])
            if not raw:
                last_err = "empty response body"
                raise RuntimeError(last_err)

            if not _content_type_is_textlike(ctype) and _looks_binary(raw):
                return (
                    FetchOutcome(
                        ok=False,
                        status=status,
                        final_url=final_url,
                        method="requests",
                        content_type=ctype,
                        content_encoding=cenc,
                        error=f"non-text response: Content-Type={ctype}",
                    ),
                    None,
                )

            html = _decode_html_bytes(raw, ctype)
            return (
                FetchOutcome(
                    ok=True,
                    status=status,
                    final_url=final_url,
                    method="requests",
                    content_type=ctype,
                    content_encoding=cenc,
                ),
                html,
            )

        except Exception as ex:
            if ("SSLError" in type(ex).__name__ or "CERTIFICATE" in str(ex).upper()) and not insecure_tls_used:
                try:
                    insecure_tls_used = True
                    headers = _rand_headers(url)
                    r = session.get(
                        url,
                        headers=headers,
                        timeout=timeout,
                        allow_redirects=True,
                        verify=False,
                        stream=True,
                    )
                    status = r.status_code
                    ctype = (r.headers.get("Content-Type") or "").strip()
                    cenc = (r.headers.get("Content-Encoding") or "").strip()
                    final_url = getattr(r, "url", url)

                    if not (200 <= status < 400):
                        last_err = f"HTTP {status}"
                        raise RuntimeError(last_err)

                    if getattr(r, "raw", None) is not None:
                        try:
                            r.raw.decode_content = True  # type: ignore[attr-defined]
                        except Exception:
                            pass

                    raw = r.raw.read(MAX_FETCH_BYTES) if getattr(r, "raw", None) else (r.content[:MAX_FETCH_BYTES])
                    if not raw:
                        last_err = "empty response body"
                        raise RuntimeError(last_err)

                    if not _content_type_is_textlike(ctype) and _looks_binary(raw):
                        return (
                            FetchOutcome(
                                ok=False,
                                status=status,
                                final_url=final_url,
                                method="requests_insecure_tls",
                                content_type=ctype,
                                content_encoding=cenc,
                                error=f"non-text response: Content-Type={ctype}",
                            ),
                            None,
                        )

                    html = _decode_html_bytes(raw, ctype)
                    return (
                        FetchOutcome(
                            ok=True,
                            status=status,
                            final_url=final_url,
                            method="requests_insecure_tls",
                            content_type=ctype,
                            content_encoding=cenc,
                        ),
                        html,
                    )
                except Exception as ex2:
                    last_err = f"insecure TLS fetch failed: {type(ex2).__name__}: {ex2}"
            else:
                last_err = f"{type(ex).__name__}: {ex}"

        time.sleep((BACKOFF_BASE ** attempt) + random.random() * 0.25)

    return FetchOutcome(ok=False, error=last_err, method="requests"), None


# -----------------------
# Metadata extraction helpers
# -----------------------
DATE_META_KEYS = [
    "article:published_time",
    "article:modified_time",
    "og:updated_time",
    "publish_date",
    "published_time",
    "date",
    "datePublished",
    "dateModified",
    "parsely-pub-date",
]

AUTHOR_META_KEYS = [
    "author",
    "article:author",
    "parsely-author",
    "byline",
    "dc.creator",
]


def _clean_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()


def _clean_title(s: str) -> str:
    s = _clean_text(s)
    s = re.sub(r"\s*[\|\-–—]\s*[^|\-–—]{2,60}$", "", s).strip()
    return s


def _clean_author(s: str) -> str:
    s = _clean_text(s)
    s = re.sub(r"^(by|written by)\s+", "", s, flags=re.I).strip()
    return s


def _extract_meta(soup: BeautifulSoup) -> Dict[str, str]:
    meta: Dict[str, str] = {}
    for m in soup.find_all("meta"):
        k = m.get("property") or m.get("name") or ""
        v = m.get("content") or ""
        k = (k or "").strip()
        v = (v or "").strip()
        if k and v and k not in meta:
            meta[k] = v
    return meta


def _extract_jsonld_objects(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    objs: List[Dict[str, Any]] = []
    for tag in soup.find_all("script", type=re.compile(r"ld\+json", re.I)):
        txt = tag.get_text(strip=True) or ""
        if not txt:
            continue
        try:
            j = json.loads(txt)
            if isinstance(j, dict):
                objs.append(j)
            elif isinstance(j, list):
                objs.extend([x for x in j if isinstance(x, dict)])
        except Exception:
            continue
    return objs


def _normalize_any_date_to_iso(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    s = s.strip()
    if not s:
        return None

    if re.match(r"^\d{4}-\d{2}-\d{2}", s):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.astimezone(timezone.utc).isoformat()
        except Exception:
            return s

    try:
        from dateutil import parser as dtparser  # type: ignore
        d = dtparser.parse(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc).isoformat()
    except Exception:
        return None


def _strip_html_tags(s: str) -> str:
    return re.sub(r"<[^>]+>", " ", s or "")


def _maybe_text_from_htmlish(s: str) -> str:
    # If it's HTML, strip tags; otherwise return as-is.
    if "<" in s and ">" in s:
        s = _strip_html_tags(s)
    return _clean_text(s)


def _deep_find_text_fields(obj: Any, keys: List[str], max_hits: int = 8) -> List[str]:
    """
    Deep search JSON for likely article body fields.
    Returns strings (cleaned), limited.
    """
    hits: List[str] = []

    def walk(x: Any) -> None:
        nonlocal hits
        if len(hits) >= max_hits:
            return
        if isinstance(x, dict):
            for k, v in x.items():
                if len(hits) >= max_hits:
                    return
                lk = str(k).lower()
                if any(lk == kk or lk.endswith(kk) for kk in keys):
                    if isinstance(v, str) and len(v.strip()) >= 120:
                        hits.append(_maybe_text_from_htmlish(v))
                    elif isinstance(v, list):
                        # join list of paragraphs
                        parts = []
                        for it in v:
                            if isinstance(it, str) and it.strip():
                                parts.append(_maybe_text_from_htmlish(it))
                        joined = _clean_text(" ".join(parts))
                        if len(joined) >= 200:
                            hits.append(joined)
                walk(v)
        elif isinstance(x, list):
            for it in x:
                if len(hits) >= max_hits:
                    return
                walk(it)

    walk(obj)
    # Dedup
    out: List[str] = []
    seen = set()
    for h in hits:
        hh = h.strip()
        if not hh:
            continue
        if hh not in seen:
            seen.add(hh)
            out.append(hh)
    return out


def _extract_next_data(soup: BeautifulSoup) -> Optional[Dict[str, Any]]:
    """
    Parse Next.js __NEXT_DATA__ if present.
    """
    tag = soup.find("script", id="__NEXT_DATA__")
    if not tag:
        return None
    txt = tag.get_text(strip=True) or ""
    if not txt:
        return None
    try:
        j = json.loads(txt)
        if isinstance(j, dict):
            return j
    except Exception:
        return None
    return None


def _extract_article_text_fallback(soup: BeautifulSoup) -> str:
    art = soup.find("article")
    if art:
        txt = _clean_text(art.get_text(" ", strip=True))
        if len(txt) > 200:
            return txt

    for sel in [
        "div.article-body",
        "div.story-body",
        "div.story",
        "div#story",
        "div#article",
        "div[itemprop='articleBody']",
        "section.article",
        "main",
    ]:
        node = soup.select_one(sel)
        if node:
            txt = _clean_text(node.get_text(" ", strip=True))
            if len(txt) > 200:
                return txt

    paras = []
    for p in soup.find_all("p"):
        t = _clean_text(p.get_text(" ", strip=True))
        if len(t) >= 40:
            paras.append(t)
    return _clean_text(" ".join(paras))


# -----------------------
# Public API
# -----------------------
def extract_article_metadata_and_text(
    session,
    url: str,
    timeout: int = TIMEOUT_DEFAULT,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], str]:
    """
    Returns: (title, author, published_date_iso, text, note)
    """
    outcome, html = _fetch_html(session, url, timeout=timeout)
    if not (outcome.ok and html):
        return None, None, None, None, f"fetch failed: {outcome.error or 'unknown'}"

    notes: List[str] = []
    if _looks_like_block_page(html):
        # IMPORTANT CHANGE: no early return — keep a warning but still extract.
        notes.append(f"possible botwall content (fetch={outcome.method}, status={outcome.status})")

    title: Optional[str] = None
    author: Optional[str] = None
    published_iso: Optional[str] = None
    text: Optional[str] = None

    # 1) trafilatura text + metadata
    try:
        t = trafilatura.extract(
            html,
            include_comments=False,
            include_tables=False,
            no_fallback=False,
        )
        if t and t.strip():
            text = t.strip()

        try:
            meta_obj = trafilatura.metadata.extract_metadata(html)
            if meta_obj:
                if meta_obj.title and not title:
                    title = _clean_title(str(meta_obj.title))
                if meta_obj.author and not author:
                    author = _clean_author(str(meta_obj.author))
                if meta_obj.date and not published_iso:
                    published_iso = _normalize_any_date_to_iso(str(meta_obj.date))
        except Exception:
            pass

    except Exception:
        pass

    # 2) soup + JSON-LD + Next.js fallback
    try:
        soup = BeautifulSoup(html, "lxml")

        if soup.title and soup.title.text:
            title = _clean_title(soup.title.text) or title

        og_title = soup.find("meta", property="og:title")
        if og_title and og_title.get("content"):
            title = _clean_title(og_title.get("content", "")) or title

        meta = _extract_meta(soup)

        # published date
        if not published_iso:
            raw_date = None
            for k in DATE_META_KEYS:
                if k in meta:
                    raw_date = (meta[k] or "").strip()
                    break
            published_iso = _normalize_any_date_to_iso(raw_date)

        # author
        if not author:
            raw_author = None
            for k in AUTHOR_META_KEYS:
                if k in meta:
                    raw_author = (meta[k] or "").strip()
                    break
            if raw_author:
                author = _clean_author(raw_author)

        # JSON-LD Article / NewsArticle
        jsonld_objs = _extract_jsonld_objects(soup)
        if jsonld_objs:
            if not published_iso:
                for obj in jsonld_objs:
                    for k in ("datePublished", "dateModified", "uploadDate", "dateCreated"):
                        v = obj.get(k)
                        if isinstance(v, str) and v.strip():
                            published_iso = _normalize_any_date_to_iso(v.strip()) or published_iso
                            break
                    if published_iso:
                        break

            if not author:
                for obj in jsonld_objs:
                    a = obj.get("author")
                    if isinstance(a, dict) and isinstance(a.get("name"), str):
                        author = _clean_author(a["name"])
                        break
                    if isinstance(a, list):
                        for it in a:
                            if isinstance(it, dict) and isinstance(it.get("name"), str):
                                author = _clean_author(it["name"])
                                break
                        if author:
                            break

            # JSON-LD articleBody
            if (not text) or len(text) < 200:
                for obj in jsonld_objs:
                    ab = obj.get("articleBody")
                    if isinstance(ab, str) and len(ab.strip()) > 200:
                        text = _maybe_text_from_htmlish(ab)
                        notes.append("text from JSON-LD articleBody")
                        break

        # Next.js __NEXT_DATA__
        if (not text) or len(text) < 200:
            next_data = _extract_next_data(soup)
            if next_data:
                # Search for likely content fields
                candidates = _deep_find_text_fields(
                    next_data,
                    keys=[
                        "articlebody",
                        "body",
                        "content",
                        "text",
                        "description",
                        "html",
                        "longdescription",
                        "story",
                        "storybody",
                        "maincontent",
                    ],
                    max_hits=6,
                )
                best = ""
                for c in candidates:
                    if len(c) > len(best):
                        best = c
                if best and len(best) >= 250:
                    text = best
                    notes.append("text from __NEXT_DATA__ (deep search)")

        # As a last resort: visible DOM scrape
        if not text or len(text) < 200:
            fallback = _extract_article_text_fallback(soup)
            if fallback and len(fallback) > 120:
                text = fallback
                notes.append("text from DOM fallback")

    except Exception as ex:
        if text:
            return title, author, published_iso, text, "; ".join(notes + [f"ok (trafilatura only; fetch={outcome.method})"])
        return None, None, None, None, f"soup parse failed: {type(ex).__name__}: {ex}"

    if title:
        title = _clean_title(title)
    if author:
        author = _clean_author(author)

    # Final note
    if text and len(text) > 80:
        return title, author, published_iso, text, "; ".join(notes + [f"ok (fetch={outcome.method}, status={outcome.status})"])

    # If we got here: no usable text
    sniff = _sniff_text(html)
    return title, author, published_iso, None, "; ".join(notes + [f"no usable text extracted (sniff='{sniff}')"])
