from __future__ import annotations

from typing import List

from .models import Article


def run_truth_layer_stub(articles: List[Article]) -> List[Article]:
    """
    Placeholder: sets empty truth fields.
    """
    for a in articles:
        # keep as None for now; UI will display blank
        a.truth_score = a.truth_score
        a.truth_label = a.truth_label
    return articles


def run_threat_layer_stub(articles: List[Article]) -> List[Article]:
    """
    Placeholder: sets empty threat fields.
    """
    for a in articles:
        a.threat_score = a.threat_score
        a.threat_level = a.threat_level
    return articles
