"""Keyword search over Agent Cards (BM25 with field weights, CJK bigrams).

Stand-in for semantic search: swap `AgentIndex` for an embedding index in phase 3
without changing the `search_agents` tool contract.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

_WORD = re.compile(r"[a-z0-9][a-z0-9+_-]*")
_CJK = re.compile(r"[㐀-鿿]+")
_STOP = {
    "the", "a", "an", "to", "of", "for", "and", "or", "in", "on", "my", "me", "i", "is", "how", "do", "can", "please",
    "幫我", "請問", "一下", "我們", "可以", "如何", "什麼", "這個", "需要", "我的", "今天", "昨天", "明天", "怎麼",
}
_FIELD_WEIGHTS = {"name": 3.0, "description": 1.0, "skill_name": 3.0, "skill_description": 1.5, "tags": 3.0, "examples": 1.0}
K1, B = 1.2, 0.75
MIN_SCORE = 1.5
RELATIVE_CUTOFF = 0.3


def tokenize(text: str) -> list[str]:
    text = text.lower()
    tokens = _WORD.findall(text)
    for run in _CJK.findall(text):
        tokens.extend([run] if len(run) == 1 else [run[i:i + 2] for i in range(len(run) - 1)])
    return [t for t in tokens if t not in _STOP]


class AgentIndex:
    def __init__(self) -> None:
        self.docs: dict[str, Counter[str]] = {}

    def add(self, agent_id: str, card: dict[str, Any]) -> None:
        tf: Counter[str] = Counter()

        def feed(field: str, text: str) -> None:
            for token in tokenize(text):
                tf[token] += _FIELD_WEIGHTS[field]

        feed("name", card.get("name", ""))
        feed("description", card.get("description", ""))
        for skill in card.get("skills", []):
            feed("skill_name", skill.get("name", ""))
            feed("skill_description", skill.get("description", ""))
            feed("tags", " ".join(skill.get("tags", [])))
            feed("examples", " ".join(skill.get("examples", [])))
        self.docs[agent_id] = tf

    def search(self, query: str, limit: int) -> list[tuple[str, float, list[str]]]:
        terms = set(tokenize(query))
        if not terms or not self.docs:
            return []
        n = len(self.docs)
        avg_len = sum(sum(d.values()) for d in self.docs.values()) / n
        scored = []
        for agent_id, tf in self.docs.items():
            length = sum(tf.values())
            score, matched = 0.0, []
            for term in terms:
                f = tf.get(term, 0.0)
                if not f:
                    continue
                df = sum(1 for d in self.docs.values() if term in d)
                idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
                score += idf * f * (K1 + 1) / (f + K1 * (1 - B + B * length / avg_len))
                matched.append(term)
            if score >= MIN_SCORE:
                scored.append((agent_id, round(score, 2), sorted(matched)))
        scored.sort(key=lambda x: x[1], reverse=True)
        if scored:
            cutoff = scored[0][1] * RELATIVE_CUTOFF
            scored = [s for s in scored if s[1] >= cutoff]
        return scored[:limit]
