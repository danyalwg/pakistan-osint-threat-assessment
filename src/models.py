from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Endpoint:
    type: str
    url: str
    note: str = ""
    enabled: bool = True

    # runtime status (not necessarily persisted)
    last_status: str = "UNKNOWN"   # WORKING / PARTIAL / FAILING / UNKNOWN
    last_error: str = ""


@dataclass
class Source:
    country: str
    name: str
    endpoints: List[Endpoint] = field(default_factory=list)
    enabled: bool = True


@dataclass
class Article:
    # -----------------------
    # Identity / origin
    # -----------------------
    id: str
    country: str
    source_name: str
    source_slug: str
    url: str

    # -----------------------
    # Core metadata
    # -----------------------
    title: str
    published_at: Optional[str] = None  # ISO8601 (best effort)
    author: Optional[str] = None
    summary: Optional[str] = None

    # -----------------------
    # Content extraction
    # -----------------------
    content_text: Optional[str] = None
    content_length: int = 0
    extraction_method: str = ""          # rss_embedded / html / sitemap / listing
    extraction_notes: List[str] = field(default_factory=list)

    # -----------------------
    # Run / session context (NEW)
    # -----------------------
    # These fields allow each fetch run to be an independent databank.
    run_id: Optional[str] = None         # e.g., "run_2026-01-11_18-42-09"
    run_created_at: Optional[str] = None # ISO8601 timestamp for the run start
    fetched_at: Optional[str] = None     # ISO8601 timestamp when this article was fetched/processed

    # -----------------------
    # Keyword shortlisting (OLD + NEW)
    # -----------------------
    # Backward compatible field (your old code already uses this)
    keywords_matched: List[str] = field(default_factory=list)

    # New: separate keyword match lists for 2-layer shortlisting
    keywords_national_matched: List[str] = field(default_factory=list)
    keywords_threat_matched: List[str] = field(default_factory=list)

    # New: explicit funnel flags (layered logic)
    national_relevant: Optional[bool] = None   # Layer-1 pass/fail
    threat_relevant: Optional[bool] = None     # Layer-2 pass/fail (only meaningful if national_relevant=True)

    # Convenience: final shortlisted flag (typically national_relevant AND threat_relevant)
    shortlisted: Optional[bool] = None

    # -----------------------
    # Stubs for later layers (existing)
    # -----------------------
    truth_score: Optional[float] = None
    truth_label: Optional[str] = None
    truth_reasons: List[str] = field(default_factory=list)

    threat_score: Optional[float] = None
    threat_level: Optional[str] = None
    threat_factors: List[str] = field(default_factory=list)

    # Raw captured fields (RSS entry, extracted meta, etc.)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            # identity/origin
            "id": self.id,
            "country": self.country,
            "source_name": self.source_name,
            "source_slug": self.source_slug,
            "url": self.url,

            # core metadata
            "title": self.title,
            "published_at": self.published_at,
            "author": self.author,
            "summary": self.summary,

            # content extraction
            "content_text": self.content_text,
            "content_length": self.content_length,
            "extraction_method": self.extraction_method,
            "extraction_notes": self.extraction_notes,

            # run/session context (NEW)
            "run_id": self.run_id,
            "run_created_at": self.run_created_at,
            "fetched_at": self.fetched_at,

            # keyword shortlisting (OLD + NEW)
            "keywords_matched": self.keywords_matched,
            "keywords_national_matched": self.keywords_national_matched,
            "keywords_threat_matched": self.keywords_threat_matched,
            "national_relevant": self.national_relevant,
            "threat_relevant": self.threat_relevant,
            "shortlisted": self.shortlisted,

            # later layers
            "truth_score": self.truth_score,
            "truth_label": self.truth_label,
            "truth_reasons": self.truth_reasons,
            "threat_score": self.threat_score,
            "threat_level": self.threat_level,
            "threat_factors": self.threat_factors,

            # raw
            "raw": self.raw,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Article":
        """
        Backward compatible loader:
        - tolerates missing new fields
        - tolerates older payloads that only had keywords_matched
        """
        # Old files may not have new per-layer keywords:
        km = list(d.get("keywords_matched", []) or [])
        kn = list(d.get("keywords_national_matched", []) or [])
        kt = list(d.get("keywords_threat_matched", []) or [])

        # If old data only has keywords_matched, you may choose to carry it into national matches
        # to avoid breaking filters. We do a conservative merge without duplicates.
        if km and not kn:
            kn = list(dict.fromkeys(km))  # preserve order, dedupe

        return Article(
            # identity/origin
            id=str(d.get("id", "") or ""),
            country=str(d.get("country", "") or ""),
            source_name=str(d.get("source_name", "") or ""),
            source_slug=str(d.get("source_slug", "") or ""),
            url=str(d.get("url", "") or ""),

            # core metadata
            title=str(d.get("title", "") or ""),
            published_at=d.get("published_at"),
            author=d.get("author"),
            summary=d.get("summary"),

            # content extraction
            content_text=d.get("content_text"),
            content_length=int(d.get("content_length", 0) or 0),
            extraction_method=str(d.get("extraction_method", "") or ""),
            extraction_notes=list(d.get("extraction_notes", []) or []),

            # run/session context (NEW)
            run_id=d.get("run_id"),
            run_created_at=d.get("run_created_at"),
            fetched_at=d.get("fetched_at"),

            # keyword shortlisting (OLD + NEW)
            keywords_matched=km,
            keywords_national_matched=kn,
            keywords_threat_matched=kt,
            national_relevant=d.get("national_relevant"),
            threat_relevant=d.get("threat_relevant"),
            shortlisted=d.get("shortlisted"),

            # later layers
            truth_score=d.get("truth_score"),
            truth_label=d.get("truth_label"),
            truth_reasons=list(d.get("truth_reasons", []) or []),
            threat_score=d.get("threat_score"),
            threat_level=d.get("threat_level"),
            threat_factors=list(d.get("threat_factors", []) or []),

            # raw
            raw=dict(d.get("raw", {}) or {}),
        )
