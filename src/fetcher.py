from __future__ import annotations

import hashlib
import random
import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .models import Article, Source


# -----------------------
# Config / heuristics
# -----------------------
RETRIES = 3
TIMEOUT = 30
BACKOFF_BASE = 1.7
MAX_FETCH_BYTES = 3_000_000

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

BAD_URL_PARTS = [
    "/tag/", "/tags/", "/topics/", "/topic/", "/category/", "/categories/",
    "/author/", "/authors/",
    "/privacy", "/terms", "/contact", "/about",
    "/login", "/signin", "/signup", "/register",
    "/epaper", "/e-paper",
    "javascript:", "mailto:",
]

ARTICLE_URL_RE = re.compile(
    r"("
    r"/\d{4}/\d{2}/\d{2}/"
    r"|/news/|/article|/story|/stories"
    r"|/latest/|/detail/|/content/|/post/|/posts/"
    r"|/world/|/pakistan/|/international/|/business/|/politics/|/sports/|/entertainment/"
    r"|/amp/|/amp$"
    r"|/(?:\d{5,})(?:[-/]|$)"
    r")",
    re.I,
)

LOOSE_ARTICLE_SIGNAL_RE = re.compile(
    r"([a-z0-9]{8,}-[a-z0-9-]{6,}|/(\d{5,})(-|/|$))",
    re.I
)


# -----------------------
# Fetch modes (NEW)
# -----------------------
FETCH_MODE_ANY = "ANY"
FETCH_MODE_LATEST_N = "LATEST_N"
FETCH_MODE_ON_DATE = "ON_DATE"
FETCH_MODE_DATE_RANGE = "DATE_RANGE"


# -----------------------
# Optional: better WAF bypass
# -----------------------
try:
    from curl_cffi import requests as curl_requests  # type: ignore
    HAS_CURL_CFFI = True
except Exception:
    curl_requests = None  # type: ignore
    HAS_CURL_CFFI = False


# -----------------------
# Utilities
# -----------------------
def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:80] if s else "source"


def normalize_url(u: str) -> str:
    u = (u or "").strip()
    u = u.split("#", 1)[0]
    return u


def _same_domain(base: str, link: str) -> bool:
    try:
        b = urlparse(base)
        l = urlparse(link)
        if not l.netloc:
            return True
        return (b.netloc or "").lower() == (l.netloc or "").lower()
    except Exception:
        return False


def is_probably_article_url(
    u: str,
    *,
    base_url: Optional[str] = None,
    allow_unknown: bool = False
) -> bool:
    u = normalize_url(u)
    if not u.startswith("http"):
        return False

    ul = u.lower()

    if any(p in ul for p in BAD_URL_PARTS):
        return False
    if "/video/" in ul or "/videos/" in ul or "/watch/" in ul or "/player/" in ul:
        return False

    if ARTICLE_URL_RE.search(u):
        return True

    if not allow_unknown:
        return False

    if base_url and not _same_domain(base_url, u):
        return False

    try:
        p = urlparse(u).path or "/"
        if p.count("/") < 2:
            return False
        if not LOOSE_ARTICLE_SIGNAL_RE.search(p):
            return False
    except Exception:
        return False

    return True


def _article_id(source_slug: str, url: str, published_at: Optional[str]) -> str:
    h = hashlib.sha256()
    h.update((source_slug + "|" + url + "|" + (published_at or "")).encode("utf-8", errors="ignore"))
    return h.hexdigest()[:24]


def rand_headers(referer: Optional[str] = None) -> Dict[str, str]:
    """
    CRITICAL: Accept-Encoding identity to reduce compressed payload surprises.
    """
    h = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Connection": "keep-alive",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    }
    if referer:
        h["Referer"] = referer
    return h


def _sniff_text(b: Optional[bytes], n: int = 220) -> str:
    if not b:
        return ""
    try:
        s = b[:n].decode("utf-8", errors="ignore")
    except Exception:
        return ""
    s = s.replace("\r", " ").replace("\n", " ").strip()
    s = re.sub(r"\s+", " ", s)
    return s[:n]


def _looks_like_html(b: Optional[bytes]) -> bool:
    s = (_sniff_text(b, 400) or "").lower()
    if not s:
        return False
    return (
        "<!doctype html" in s
        or "<html" in s
        or "<head" in s
        or "<body" in s
        or "just a moment" in s
        or "access denied" in s
        or "forbidden" in s
        or "attention required" in s
        or "captcha" in s
    )


def _looks_like_xml(b: Optional[bytes]) -> bool:
    s = (_sniff_text(b, 200) or "").lower()
    if not s:
        return False
    return (
        s.startswith("<?xml")
        or s.startswith("<rss")
        or s.startswith("<feed")
        or s.startswith("<urlset")
        or s.startswith("<sitemapindex")
    )


def _ctype_is_xmlish(ctype: str) -> bool:
    cl = (ctype or "").lower()
    return ("xml" in cl) or ("rss" in cl) or ("atom" in cl)


# -----------------------
# Smart HTTP client
# -----------------------
@dataclass
class FetchResult:
    ok: bool
    status: Optional[int] = None
    error: Optional[str] = None
    content_type: str = ""
    insecure_tls_used: bool = False
    sniff: str = ""


class SmartHTTP:
    """
    Robust GET:
    - retries + backoff
    - rotating headers
    - optional curl_cffi fallback
    - uses provided requests.Session (already Tor-proxied in your app)

    CRITICAL FIX:
    - when stream=True, set r.raw.decode_content=True before reading.
    """
    def __init__(self, sess: requests.Session) -> None:
        self.sess = sess

    def _curl_cffi_get(
        self,
        url: str,
        allow_redirects: bool,
        referer: Optional[str],
    ) -> Tuple[FetchResult, Optional[bytes], Dict[str, str]]:
        if not (HAS_CURL_CFFI and curl_requests is not None):
            return FetchResult(ok=False, error="curl_cffi not available"), None, {}

        hdrs = rand_headers(referer=referer)
        rr = curl_requests.get(
            url,
            headers=hdrs,
            timeout=TIMEOUT,
            allow_redirects=allow_redirects,
            impersonate="chrome",
            proxies=self.sess.proxies if self.sess.proxies else None,
        )
        ctype2 = (rr.headers.get("Content-Type") or "").strip()
        data2 = rr.content[:MAX_FETCH_BYTES]
        fr2 = FetchResult(
            ok=(200 <= rr.status_code < 400),
            status=rr.status_code,
            content_type=ctype2,
            sniff=_sniff_text(data2),
        )
        hdr2 = {k.lower(): v for k, v in rr.headers.items()}
        return fr2, data2, hdr2

    def get(
        self,
        url: str,
        allow_redirects: bool = True,
        expect: str = "any",  # "any" | "xml"
    ) -> Tuple[FetchResult, Optional[bytes], Dict[str, str]]:
        url = normalize_url(url)
        parsed = urlparse(url)
        host = parsed.hostname or ""
        referer = f"{parsed.scheme}://{host}/" if host else None

        last_err: Optional[str] = None
        insecure_used = False

        for attempt in range(1, RETRIES + 1):
            try:
                h = rand_headers(referer=referer)
                r = self.sess.get(
                    url,
                    headers=h,
                    timeout=TIMEOUT,
                    allow_redirects=allow_redirects,
                    stream=True
                )
                status = r.status_code
                ctype = (r.headers.get("Content-Type") or "").strip()

                # Blocked: try curl_cffi for 403/429
                if not (200 <= status < 400):
                    if status in (403, 429) and HAS_CURL_CFFI:
                        fr2, data2, hdr2 = self._curl_cffi_get(url, allow_redirects, referer)
                        if fr2.ok and data2:
                            return fr2, data2, hdr2
                    last_err = f"HTTP {status}"
                    raise RuntimeError(last_err)

                # IMPORTANT: enable transparent decompression when reading raw stream
                if getattr(r, "raw", None) is not None:
                    try:
                        r.raw.decode_content = True  # type: ignore[attr-defined]
                    except Exception:
                        pass

                data = r.raw.read(MAX_FETCH_BYTES) if r.raw else r.content[:MAX_FETCH_BYTES]
                hdr = {k.lower(): v for k, v in r.headers.items()}
                sniff = _sniff_text(data)
                fr = FetchResult(
                    ok=True,
                    status=status,
                    content_type=ctype,
                    insecure_tls_used=insecure_used,
                    sniff=sniff
                )

                # If we expected XML but got HTML, try curl_cffi even if HTTP=200.
                if expect == "xml":
                    xmlish = _ctype_is_xmlish(ctype) or _looks_like_xml(data)
                    if (not xmlish) and _looks_like_html(data) and HAS_CURL_CFFI:
                        fr2, data2, hdr2 = self._curl_cffi_get(url, allow_redirects, referer)
                        if fr2.ok and data2 and (_ctype_is_xmlish(fr2.content_type) or _looks_like_xml(data2)):
                            return fr2, data2, hdr2
                        return FetchResult(
                            ok=False,
                            status=status,
                            content_type=ctype,
                            error="Expected XML but received HTML/blocked page",
                            sniff=sniff,
                        ), data, hdr

                return fr, data, hdr

            except requests.exceptions.SSLError as e:
                last_err = str(e)

                if HAS_CURL_CFFI:
                    try:
                        fr2, data2, hdr2 = self._curl_cffi_get(url, allow_redirects, referer)
                        if fr2.ok and data2:
                            if expect != "xml" or _ctype_is_xmlish(fr2.content_type) or _looks_like_xml(data2):
                                return fr2, data2, hdr2
                    except Exception:
                        pass

                if not insecure_used:
                    try:
                        insecure_used = True
                        h = rand_headers(referer=referer)
                        r = self.sess.get(
                            url,
                            headers=h,
                            timeout=TIMEOUT,
                            allow_redirects=allow_redirects,
                            verify=False,
                            stream=True,
                        )
                        status = r.status_code
                        ctype = (r.headers.get("Content-Type") or "").strip()

                        if getattr(r, "raw", None) is not None:
                            try:
                                r.raw.decode_content = True  # type: ignore[attr-defined]
                            except Exception:
                                pass

                        data = r.raw.read(MAX_FETCH_BYTES) if r.raw else r.content[:MAX_FETCH_BYTES]
                        hdr = {k.lower(): v for k, v in r.headers.items()}
                        sniff = _sniff_text(data)
                        return FetchResult(
                            ok=(200 <= status < 400),
                            status=status,
                            content_type=ctype,
                            insecure_tls_used=True,
                            sniff=sniff
                        ), data, hdr
                    except Exception as e2:
                        last_err = f"TLS verify failed then insecure failed: {e2}"

            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                last_err = str(e)

                if HAS_CURL_CFFI and expect == "xml":
                    try:
                        fr2, data2, hdr2 = self._curl_cffi_get(url, allow_redirects, referer)
                        if fr2.ok and data2 and (_ctype_is_xmlish(fr2.content_type) or _looks_like_xml(data2)):
                            return fr2, data2, hdr2
                    except Exception:
                        pass

            except Exception as e:
                last_err = str(e)

            time.sleep((BACKOFF_BASE ** attempt) + random.random() * 0.25)

        return FetchResult(ok=False, error=last_err, insecure_tls_used=insecure_used), None, {}


# -----------------------
# XML parsing helpers
# -----------------------
def parse_sitemap_urls(xml_bytes: bytes, base_url: str) -> List[str]:
    soup = BeautifulSoup(xml_bytes, "xml")
    urls = [loc.text.strip() for loc in soup.find_all("loc") if loc and loc.text]
    out: List[str] = []
    for u in urls:
        u = normalize_url(u)
        if not u:
            continue
        if u.startswith("/"):
            u = urljoin(base_url, u)
        if u not in out:
            out.append(u)
    return out


def parse_sitemap_index_urls(xml_bytes: bytes, base_url: str) -> List[str]:
    soup = BeautifulSoup(xml_bytes, "xml")
    urls = [loc.text.strip() for loc in soup.find_all("loc") if loc and loc.text]
    out: List[str] = []
    for u in urls:
        u = normalize_url(u)
        if not u:
            continue
        if u.startswith("/"):
            u = urljoin(base_url, u)
        if u not in out:
            out.append(u)
    return out


def discover_from_html_listing(html_bytes: bytes, base_url: str) -> List[str]:
    soup = BeautifulSoup(html_bytes, "lxml")
    links: List[str] = []
    for a in soup.find_all("a", href=True):
        href = (a.get("href", "") or "").strip()
        if not href:
            continue
        if href.startswith("/"):
            href = urljoin(base_url, href)
        href = normalize_url(href)
        if href.startswith("http"):
            links.append(href)

    out: List[str] = []
    for u in links:
        if is_probably_article_url(u, base_url=base_url, allow_unknown=False) and u not in out:
            out.append(u)
    return out


def discover_feed_links_from_directory_page(html_bytes: bytes, base_url: str) -> List[str]:
    soup = BeautifulSoup(html_bytes, "lxml")
    cands: List[str] = []

    for tag in soup.find_all("link"):
        rel = tag.get("rel") or []
        if isinstance(rel, str):
            rel = [rel]
        rel = [r.lower() for r in rel]
        t = (tag.get("type") or "").lower()
        href = (tag.get("href") or "").strip()
        if not href:
            continue
        if "alternate" in rel and ("rss" in t or "atom" in t or "xml" in t):
            if href.startswith("/"):
                href = urljoin(base_url, href)
            href = normalize_url(href)
            if href.startswith("http") and href not in cands:
                cands.append(href)

    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        if href.startswith("/"):
            href = urljoin(base_url, href)
        href = normalize_url(href)
        low = href.lower()
        if any(x in low for x in ["rss", "feed", "atom", ".xml", ".rss"]):
            if href.startswith("http") and href not in cands:
                cands.append(href)

    same = [u for u in cands if _same_domain(base_url, u)]
    other = [u for u in cands if u not in same]
    return (same + other)[:50]


# -----------------------
# RSS parsing with metadata
# -----------------------
@dataclass
class RSSItem:
    url: str
    title: str = ""
    summary: str = ""
    author: str = ""
    published_at: Optional[str] = None


def _parse_date_to_iso(dt_obj) -> Optional[str]:
    if dt_obj is None:
        return None

    try:
        import time as _time
        if isinstance(dt_obj, _time.struct_time):
            return datetime(*dt_obj[:6], tzinfo=timezone.utc).isoformat()
    except Exception:
        pass

    if isinstance(dt_obj, datetime):
        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        return dt_obj.astimezone(timezone.utc).isoformat()

    if isinstance(dt_obj, str):
        s = dt_obj.strip()
        if re.match(r"^\d{4}-\d{2}-\d{2}", s):
            try:
                d = datetime.fromisoformat(s.replace("Z", "+00:00"))
                if d.tzinfo is None:
                    d = d.replace(tzinfo=timezone.utc)
                return d.astimezone(timezone.utc).isoformat()
            except Exception:
                return s
        return None

    return None


def parse_rss_items(xml_bytes: bytes, base_url: str) -> List[RSSItem]:
    try:
        import feedparser
    except Exception:
        soup = BeautifulSoup(xml_bytes, "xml")
        out_urls: List[str] = []
        for it in soup.find_all(["item", "entry"]):
            link = it.find("link")
            if link and link.text:
                out_urls.append(link.text.strip())
        return [RSSItem(url=urljoin(base_url, u) if u.startswith("/") else u) for u in out_urls]

    feed = feedparser.parse(xml_bytes)
    out: List[RSSItem] = []

    for e in feed.entries or []:
        url = (e.get("link") or "").strip()
        if not url and "links" in e:
            for lk in e.get("links") or []:
                if (lk.get("rel") or "").lower() == "alternate" and lk.get("href"):
                    url = (lk.get("href") or "").strip()
                    break

        if not url:
            guid = (e.get("id") or e.get("guid") or "").strip()
            if guid.startswith("http"):
                url = guid

        if not url:
            continue

        if url.startswith("/"):
            url = urljoin(base_url, url)
        url = normalize_url(url)

        title = (e.get("title") or "").strip()
        author = (e.get("author") or "").strip()

        summary = ""
        if e.get("summary"):
            summary = str(e.get("summary") or "").strip()
        elif e.get("description"):
            summary = str(e.get("description") or "").strip()

        pub_iso = None
        if e.get("published_parsed"):
            pub_iso = _parse_date_to_iso(e.get("published_parsed"))
        if not pub_iso and e.get("updated_parsed"):
            pub_iso = _parse_date_to_iso(e.get("updated_parsed"))
        if not pub_iso and e.get("published"):
            pub_iso = _parse_date_to_iso(str(e.get("published")))
        if not pub_iso and e.get("updated"):
            pub_iso = _parse_date_to_iso(str(e.get("updated")))

        out.append(RSSItem(url=url, title=title, summary=summary, author=author, published_at=pub_iso))

    dedup: List[RSSItem] = []
    seen = set()
    for it in out:
        if it.url not in seen:
            seen.add(it.url)
            dedup.append(it)
    return dedup


# -----------------------
# Fast HTML published date sniffing
# -----------------------
_DATE_META_KEYS = [
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


def _extract_jsonld_dates(soup: BeautifulSoup) -> List[str]:
    out: List[str] = []
    for tag in soup.find_all("script", type=re.compile(r"ld\+json", re.I)):
        txt = tag.get_text(strip=True) or ""
        if not txt:
            continue
        try:
            import json
            j = json.loads(txt)
            candidates = []
            if isinstance(j, dict):
                candidates.append(j)
            elif isinstance(j, list):
                candidates.extend([x for x in j if isinstance(x, dict)])
            for obj in candidates:
                for k in ("datePublished", "dateModified", "uploadDate", "dateCreated"):
                    v = obj.get(k)
                    if isinstance(v, str) and v.strip():
                        out.append(v.strip())
        except Exception:
            continue
    return out


def _normalize_any_date_to_iso(s: str) -> Optional[str]:
    s = (s or "").strip()
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


def sniff_published_at_fast(http: SmartHTTP, url: str) -> Optional[str]:
    fr, data, _ = http.get(url, allow_redirects=True, expect="any")
    if not fr.ok or not data:
        return None

    if not _looks_like_html(data) and ("html" not in (fr.content_type or "").lower()):
        return None

    try:
        html = data.decode("utf-8", errors="ignore")
    except Exception:
        return None

    soup = BeautifulSoup(html, "lxml")
    meta = _extract_meta(soup)

    for k in _DATE_META_KEYS:
        v = meta.get(k)
        if v:
            iso = _normalize_any_date_to_iso(v)
            if iso:
                return iso

    for v in _extract_jsonld_dates(soup):
        iso = _normalize_any_date_to_iso(v)
        if iso:
            return iso

    return None


# -----------------------
# Date filtering utilities
# -----------------------
def _iso_to_date(iso_str: Optional[str]) -> Optional[date]:
    if not iso_str:
        return None
    s = iso_str.strip()
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc).date()
    except Exception:
        m = re.match(r"^(\d{4}-\d{2}-\d{2})", s)
        if m:
            try:
                return datetime.fromisoformat(m.group(1)).date()
            except Exception:
                return None
    return None


def _in_date_range(d: Optional[date], start: Optional[date], end: Optional[date]) -> bool:
    if d is None:
        return False
    if start and d < start:
        return False
    if end and d > end:
        return False
    return True


# -----------------------
# Core: discovery / fetch
# -----------------------
def fetch_discovery_items(
    session: requests.Session,
    source: Source,
    limit_items: int = 100,
    timeout: int = 30,
    *,
    mode: str = FETCH_MODE_ANY,
    latest_n: Optional[int] = None,
    on_date: Optional[date] = None,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    prefetch_multiplier: int = 6,
    allow_unknown_article_urls: bool = False,
) -> Tuple[List[Article], List[str]]:
    http = SmartHTTP(session)
    log: List[str] = []

    source_slug = _safe_slug(source.name)
    base_url_guess = ""
    if source.endpoints:
        try:
            base_url_guess = source.endpoints[0].url
        except Exception:
            base_url_guess = ""

    mode = (mode or FETCH_MODE_ANY).strip().upper()
    if mode not in (FETCH_MODE_ANY, FETCH_MODE_LATEST_N, FETCH_MODE_ON_DATE, FETCH_MODE_DATE_RANGE):
        mode = FETCH_MODE_ANY

    target_n = int(latest_n) if (latest_n is not None and int(latest_n) > 0) else int(limit_items)
    if target_n <= 0:
        target_n = 1

    want_date_filter = mode in (FETCH_MODE_ON_DATE, FETCH_MODE_DATE_RANGE)
    max_candidates = max(target_n * max(1, int(prefetch_multiplier)), target_n)

    rss_items: List[RSSItem] = []
    url_candidates: List[str] = []

    def push_url(u: str) -> None:
        u = normalize_url(u)
        if not u or not u.startswith("http"):
            return
        if u not in url_candidates:
            url_candidates.append(u)

    def push_rss_item(it: RSSItem) -> None:
        if not it.url.startswith("http"):
            return
        if all(x.url != it.url for x in rss_items):
            rss_items.append(it)

    enabled_endpoints = [e for e in (source.endpoints or []) if getattr(e, "enabled", True)]
    if not enabled_endpoints:
        return [], [f"[{source.country} | {source.name}] No enabled endpoints configured."]

    endpoint_used = None
    discovery_method = ""
    for ep in enabled_endpoints:
        ep_type = (ep.type or "").strip().upper()
        ep_url = (ep.url or "").strip()
        if not ep_url:
            continue

        endpoint_used = ep_url
        base_url_guess = ep_url

        if ep_type == "RSS":
            discovery_method = "rss"
            fr, data, _ = http.get(ep_url, allow_redirects=True, expect="xml")
            if not fr.ok or not data:
                log.append(f"[{source.country} | {source.name}] RSS fetch failed: {ep_url} err={fr.error}")
                continue

            items = parse_rss_items(data, ep_url)
            log.append(f"[{source.country} | {source.name}] RSS parsed: {len(items)} entries from {ep_url}")

            for it in items:
                push_rss_item(it)
                if len(rss_items) >= max_candidates:
                    break

            if rss_items:
                break
            continue

        if ep_type == "FEED_DIRECTORY":
            discovery_method = "feed_directory"
            fr, data, _ = http.get(ep_url, allow_redirects=True, expect="any")
            if not fr.ok or not data:
                log.append(f"[{source.country} | {source.name}] FEED_DIRECTORY fetch failed: {ep_url} err={fr.error}")
                continue

            feed_links = discover_feed_links_from_directory_page(data, ep_url)
            log.append(f"[{source.country} | {source.name}] FEED_DIRECTORY found {len(feed_links)} feed candidates")

            def feed_score(u: str) -> Tuple[int, int, int]:
                same = 1 if _same_domain(ep_url, u) else 0
                low = u.lower()
                has_rss = 1 if ("rss" in low or "feed" in low or "atom" in low) else 0
                return (same, has_rss, -len(u))

            feed_links_sorted = sorted(feed_links, key=feed_score, reverse=True)

            picked = None
            for feed_url in feed_links_sorted[:15]:
                fr2, data2, _ = http.get(feed_url, allow_redirects=True, expect="xml")
                if fr2.ok and data2 and (_ctype_is_xmlish(fr2.content_type) or _looks_like_xml(data2)):
                    parsed_items = parse_rss_items(data2, feed_url)
                    if parsed_items:
                        picked = feed_url
                        for it in parsed_items:
                            push_rss_item(it)
                            if len(rss_items) >= max_candidates:
                                break
                        break

            if picked:
                log.append(f"[{source.country} | {source.name}] FEED_DIRECTORY picked feed: {picked} items={len(rss_items)}")
                break

            log.append(f"[{source.country} | {source.name}] FEED_DIRECTORY could not validate any feed.")
            continue

        if ep_type == "HTML_LISTING":
            discovery_method = "html_listing"
            fr, data, _ = http.get(ep_url, allow_redirects=True, expect="any")
            if not fr.ok or not data:
                log.append(f"[{source.country} | {source.name}] HTML_LISTING fetch failed: {ep_url} err={fr.error}")
                continue

            urls = discover_from_html_listing(data, ep_url)
            log.append(f"[{source.country} | {source.name}] HTML_LISTING discovered {len(urls)} urls")
            for u in urls:
                if is_probably_article_url(u, base_url=ep_url, allow_unknown=allow_unknown_article_urls):
                    push_url(u)
                    if len(url_candidates) >= max_candidates:
                        break

            if url_candidates:
                break
            continue

        if ep_type == "SITEMAP_INDEX":
            discovery_method = "sitemap"
            fr, data, _ = http.get(ep_url, allow_redirects=True, expect="xml")
            if not fr.ok or not data:
                log.append(f"[{source.country} | {source.name}] SITEMAP_INDEX fetch failed: {ep_url} err={fr.error}")
                continue

            if b"<sitemapindex" in data.lower():
                child_sitemaps = parse_sitemap_index_urls(data, ep_url)
                log.append(f"[{source.country} | {source.name}] Sitemap index has {len(child_sitemaps)} child sitemaps")
                for sm in child_sitemaps[:30]:
                    fr2, data2, _ = http.get(sm, allow_redirects=True, expect="xml")
                    if not fr2.ok or not data2:
                        continue
                    urls = parse_sitemap_urls(data2, ep_url)
                    for u in urls:
                        if is_probably_article_url(u, base_url=ep_url, allow_unknown=allow_unknown_article_urls):
                            push_url(u)
                            if len(url_candidates) >= max_candidates:
                                break
                    if len(url_candidates) >= max_candidates:
                        break
            else:
                urls = parse_sitemap_urls(data, ep_url)
                log.append(f"[{source.country} | {source.name}] Sitemap urlset has {len(urls)} urls")
                for u in urls:
                    if is_probably_article_url(u, base_url=ep_url, allow_unknown=allow_unknown_article_urls):
                        push_url(u)
                        if len(url_candidates) >= max_candidates:
                            break

            if url_candidates:
                break
            continue

        log.append(f"[{source.country} | {source.name}] Unknown endpoint type: {ep_type} url={ep_url}")

    if not endpoint_used:
        return [], [f"[{source.country} | {source.name}] No endpoint used (configuration issue)."]

    items: List[Article] = []
    seen_urls: Set[str] = set()

    def make_article(
        url: str,
        *,
        title: str = "",
        author: str = "",
        summary: str = "",
        published_at: Optional[str] = None,
        extraction_method: str = "",
        raw_extra: Optional[Dict] = None,
    ) -> Article:
        url2 = normalize_url(url)
        pub = published_at
        aid = _article_id(source_slug, url2, pub)
        a = Article(
            id=aid,
            country=source.country,
            source_name=source.name,
            source_slug=source_slug,
            url=url2,
            title=title or url2,
            published_at=pub,
            author=author or None,
            summary=summary or None,
            content_text=None,
            content_length=0,
            extraction_method=extraction_method,
            extraction_notes=[],
            raw={
                "discovery_method": discovery_method,
                "endpoint_used": endpoint_used,
                "fetched_at": _iso_now(),
            },
        )
        if raw_extra:
            try:
                a.raw.update(raw_extra)
            except Exception:
                pass
        return a

    if rss_items:
        for it in rss_items:
            if it.url in seen_urls:
                continue
            seen_urls.add(it.url)
            items.append(make_article(
                it.url,
                title=it.title,
                author=it.author,
                summary=it.summary,
                published_at=it.published_at,
                extraction_method="rss",
                raw_extra={"rss": {"published_at": it.published_at}},
            ))
            if len(items) >= max_candidates:
                break
    else:
        for u in url_candidates:
            if u in seen_urls:
                continue
            seen_urls.add(u)
            items.append(make_article(
                u,
                extraction_method=discovery_method or "listing",
            ))
            if len(items) >= max_candidates:
                break

    if want_date_filter:
        missing = [a for a in items if not a.published_at]
        if missing:
            log.append(f"[{source.country} | {source.name}] Date filter enabled; sniffing published dates for {len(missing)} items...")
        for idx, a in enumerate(missing):
            pub_iso = sniff_published_at_fast(http, a.url)
            if pub_iso:
                a.published_at = pub_iso
                a.id = _article_id(source_slug, a.url, a.published_at)
            else:
                a.extraction_notes.append("date_sniff_failed")
            if (idx + 1) % 25 == 0:
                log.append(f"[{source.country} | {source.name}] Date sniff progress: {idx+1}/{len(missing)}")

    if mode == FETCH_MODE_ON_DATE:
        if on_date is None:
            raise ValueError("mode=ON_DATE requires on_date=<datetime.date>")
        filtered: List[Article] = []
        for a in items:
            d = _iso_to_date(a.published_at)
            if d == on_date:
                filtered.append(a)
        items = filtered
        log.append(f"[{source.country} | {source.name}] ON_DATE={on_date.isoformat()} kept {len(items)} items")

    elif mode == FETCH_MODE_DATE_RANGE:
        if date_from is None and date_to is None:
            raise ValueError("mode=DATE_RANGE requires date_from and/or date_to")
        filtered = []
        for a in items:
            d = _iso_to_date(a.published_at)
            if _in_date_range(d, date_from, date_to):
                filtered.append(a)
        items = filtered
        log.append(
            f"[{source.country} | {source.name}] DATE_RANGE {date_from.isoformat() if date_from else '...'} -> "
            f"{date_to.isoformat() if date_to else '...'} kept {len(items)} items"
        )

    if mode in (FETCH_MODE_LATEST_N, FETCH_MODE_ON_DATE, FETCH_MODE_DATE_RANGE):
        def sort_key(a: Article) -> Tuple[int, str]:
            d = a.published_at or ""
            return (1 if d else 0, d)
        items.sort(key=sort_key, reverse=True)

    items = items[:target_n]

    log.append(
        f"[{source.country} | {source.name}] Discovery={discovery_method} endpoint={endpoint_used} "
        f"mode={mode} returned={len(items)} (target={target_n})"
    )

    return items, log
