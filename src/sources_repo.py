from __future__ import annotations

import json
import os
from typing import List, Tuple

from .models import Endpoint, Source


def _data_paths(base_dir: str) -> Tuple[str, str, str]:
    data_dir = os.path.join(base_dir, "data")
    sources_path = os.path.join(data_dir, "sources.json")
    keywords_path = os.path.join(data_dir, "keywords.json")
    news_dir = os.path.join(data_dir, "news")
    return sources_path, keywords_path, news_dir


def ensure_default_data_files(base_dir: str) -> None:
    sources_path, keywords_path, news_dir = _data_paths(base_dir)
    os.makedirs(os.path.dirname(sources_path), exist_ok=True)
    os.makedirs(news_dir, exist_ok=True)

    # If user forgot to create these, fail-safe with very small defaults.
    if not os.path.isfile(sources_path):
        with open(sources_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "sources": []}, f, ensure_ascii=False, indent=2)

    if not os.path.isfile(keywords_path):
        with open(keywords_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "enabled": True, "keywords": ["Pakistan"]}, f, ensure_ascii=False, indent=2)


def load_sources(base_dir: str) -> List[Source]:
    sources_path, _, _ = _data_paths(base_dir)
    with open(sources_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    out: List[Source] = []
    for s in data.get("sources", []):
        endpoints = []
        for e in s.get("endpoints", []):
            endpoints.append(
                Endpoint(
                    type=str(e.get("type", "")).strip(),
                    url=str(e.get("url", "")).strip(),
                    note=str(e.get("note", "")).strip(),
                    enabled=bool(e.get("enabled", True)),
                )
            )
        out.append(
            Source(
                country=str(s.get("country", "")).strip(),
                name=str(s.get("name", "")).strip(),
                enabled=bool(s.get("enabled", True)),
                endpoints=endpoints,
            )
        )
    return out


def save_sources(base_dir: str, sources: List[Source]) -> None:
    sources_path, _, _ = _data_paths(base_dir)
    payload = {"version": 1, "sources": []}
    for s in sources:
        payload["sources"].append({
            "country": s.country,
            "name": s.name,
            "enabled": s.enabled,
            "endpoints": [
                {"type": e.type, "url": e.url, "note": e.note, "enabled": e.enabled}
                for e in s.endpoints
            ],
        })
    with open(sources_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
