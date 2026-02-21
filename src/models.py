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
    last_status: str = "UNKNOWN"  # WORKING / PARTIAL / FAILING / UNKNOWN
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
    extraction_method: str = ""  # rss_embedded / html / sitemap / listing
    extraction_notes: List[str] = field(default_factory=list)

    # -----------------------
    # Run / session context
    # -----------------------
    run_id: Optional[str] = None
    run_created_at: Optional[str] = None
    fetched_at: Optional[str] = None

    # -----------------------
    # Keyword shortlisting (existing + explicit)
    # -----------------------
    # Backward compatible
    keywords_matched: List[str] = field(default_factory=list)

    # Two-layer lists
    keywords_national_matched: List[str] = field(default_factory=list)
    keywords_threat_matched: List[str] = field(default_factory=list)

    # Funnel flags
    national_relevant: Optional[bool] = None
    threat_relevant: Optional[bool] = None
    shortlisted: Optional[bool] = None

    # Explicit spec fields (Layer 1 outputs)
    kw_national_hits: List[str] = field(default_factory=list)
    kw_threat_hits: List[str] = field(default_factory=list)

    # -----------------------
    # Layer 2 (Algorithmic scoring)
    # -----------------------
    relevance_score: Optional[float] = None          # R (0-100)
    evidence_strength: Optional[str] = None          # LOW/MED/HIGH
    evidence_numeric: Optional[float] = None         # E (25/60/90)
    urgency_score: Optional[float] = None            # U (0-100)
    keyword_intensity: Optional[float] = None        # K (0-100)
    prepriority_score: Optional[float] = None        # PrePriority (0-100)
    prepriority_bucket: Optional[str] = None         # LOW/MEDIUM/HIGH/CRITICAL

    # -----------------------
    # Layer 3 (LLM threat severity)
    # -----------------------
    threat_score: Optional[float] = None             # T (0-100)
    threat_level: Optional[str] = None               # LOW/MED/HIGH/CRITICAL
    threat_vector: Optional[str] = None              # MILITARY/TERROR/CYBER/DIPLO/ECON/INTERNAL/OTHER
    one_liner_threat: Optional[str] = None
    reasons: List[str] = field(default_factory=list) # 2-4 bullets

    # -----------------------
    # Final Risk Index
    # -----------------------
    risk_index: Optional[float] = None

    # -----------------------
    # Stubs / legacy (kept)
    # -----------------------
    truth_score: Optional[float] = None
    truth_label: Optional[str] = None
    truth_reasons: List[str] = field(default_factory=list)

    # legacy: threat_factors still kept for future or compatibility
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

            # run/session context
            "run_id": self.run_id,
            "run_created_at": self.run_created_at,
            "fetched_at": self.fetched_at,

            # keyword shortlisting
            "keywords_matched": self.keywords_matched,
            "keywords_national_matched": self.keywords_national_matched,
            "keywords_threat_matched": self.keywords_threat_matched,
            "national_relevant": self.national_relevant,
            "threat_relevant": self.threat_relevant,
            "shortlisted": self.shortlisted,

            # explicit Layer-1 outputs
            "kw_national_hits": self.kw_national_hits,
            "kw_threat_hits": self.kw_threat_hits,

            # layer 2
            "relevance_score": self.relevance_score,
            "evidence_strength": self.evidence_strength,
            "evidence_numeric": self.evidence_numeric,
            "urgency_score": self.urgency_score,
            "keyword_intensity": self.keyword_intensity,
            "prepriority_score": self.prepriority_score,
            "prepriority_bucket": self.prepriority_bucket,

            # layer 3
            "threat_score": self.threat_score,
            "threat_level": self.threat_level,
            "threat_vector": self.threat_vector,
            "one_liner_threat": self.one_liner_threat,
            "reasons": self.reasons,

            # final
            "risk_index": self.risk_index,

            # legacy / stubs
            "truth_score": self.truth_score,
            "truth_label": self.truth_label,
            "truth_reasons": self.truth_reasons,
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
        - tolerates GUI older runs that stored kw_* inside raw
        """
        km = list(d.get("keywords_matched", []) or [])
        kn = list(d.get("keywords_national_matched", []) or [])
        kt = list(d.get("keywords_threat_matched", []) or [])

        # carry old keywords_matched into national matches if needed
        if km and not kn:
            kn = list(dict.fromkeys(km))

        raw = dict(d.get("raw", {}) or {})

        # explicit kw fields may be missing, try raw fallback
        kw_nat = list(d.get("kw_national_hits", []) or []) or list(raw.get("kw_national_hits", []) or [])
        kw_thr = list(d.get("kw_threat_hits", []) or []) or list(raw.get("kw_threat_hits", []) or [])

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

            # run/session context
            run_id=d.get("run_id"),
            run_created_at=d.get("run_created_at"),
            fetched_at=d.get("fetched_at"),

            # keyword shortlisting
            keywords_matched=km,
            keywords_national_matched=kn,
            keywords_threat_matched=kt,
            national_relevant=d.get("national_relevant"),
            threat_relevant=d.get("threat_relevant"),
            shortlisted=d.get("shortlisted"),

            # explicit Layer-1 outputs
            kw_national_hits=kw_nat,
            kw_threat_hits=kw_thr,

            # layer 2
            relevance_score=d.get("relevance_score"),
            evidence_strength=d.get("evidence_strength"),
            evidence_numeric=d.get("evidence_numeric"),
            urgency_score=d.get("urgency_score"),
            keyword_intensity=d.get("keyword_intensity"),
            prepriority_score=d.get("prepriority_score"),
            prepriority_bucket=d.get("prepriority_bucket"),

            # layer 3
            threat_score=d.get("threat_score"),
            threat_level=d.get("threat_level"),
            threat_vector=d.get("threat_vector"),
            one_liner_threat=d.get("one_liner_threat"),
            reasons=list(d.get("reasons", []) or []),

            # final
            risk_index=d.get("risk_index"),

            # legacy/stubs
            truth_score=d.get("truth_score"),
            truth_label=d.get("truth_label"),
            truth_reasons=list(d.get("truth_reasons", []) or []),
            threat_factors=list(d.get("threat_factors", []) or []),

            # raw
            raw=raw,
        )
