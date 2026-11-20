"""Agent Card search for `search_agents`.

- `AgentIndex`: keyword search (BM25 with field weights, CJK bigrams). No dependencies.
- `HybridIndex`: the keyword hits plus an embedding search, so a request that shares no words with a card
  ("從家裡沒辦法連上公司內網" vs. the VPN skill) still finds it. Needs `pip install fastembed`; the
  multilingual model (about 220 MB) is downloaded to .cache/fastembed on first use.

`make_index` picks one from POC_SEARCH (auto | keyword | hybrid). The tool contract is the same for both.
"""
from __future__ import annotations

import logging
import math
import re
import threading
from collections import Counter
from typing import Any, Callable

from poc.settings import ROOT, Settings

log = logging.getLogger("poc.search")

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
    mode = "keyword-bm25"

    def __init__(self) -> None:
        self.docs: dict[str, Counter[str]] = {}

    def prepare(self) -> None:
        pass

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


EMBEDDING_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
# Cosine similarity a card needs to count as a match on meaning alone. With the demo catalog, unrelated
# requests (meeting rooms, weather, lunch) stay below 0.39 and paraphrased real ones score 0.44 or more.
SEMANTIC_MIN = 0.42
RRF_K = 60

Embedder = Callable[[list[str]], list[list[float]]]
_model_lock = threading.Lock()
_model: Any = None


def fastembed_embedder() -> Embedder:
    """Load the embedding model once per process (raises ImportError without fastembed)."""
    global _model
    from fastembed import TextEmbedding
    with _model_lock:
        if _model is None:
            _model = TextEmbedding(EMBEDDING_MODEL, cache_dir=str(ROOT / ".cache" / "fastembed"))
    return lambda texts: [list(map(float, v)) for v in _model.embed(texts)]


def _unit(v: list[float]) -> list[float]:
    norm = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / norm for x in v]


class HybridIndex:
    """BM25 hits plus embedding matches, ranked by reciprocal rank fusion.

    Each skill (name, description, tags, examples) and each example sentence is embedded on its own; an
    agent's similarity is its best one, so one strong skill is not diluted by the others.
    """

    mode = "hybrid-bm25-embedding"

    def __init__(self, embed: Embedder):
        self.keyword = AgentIndex()
        self.embed = embed
        self._texts: list[tuple[str, str]] = []
        self._vectors: list[tuple[str, list[float]]] | None = None

    def add(self, agent_id: str, card: dict[str, Any]) -> None:
        self.keyword.add(agent_id, card)
        for skill in card.get("skills", []):
            self._texts.append((agent_id, " ".join([skill.get("name", ""), skill.get("description", ""),
                                                    " ".join(skill.get("tags", [])),
                                                    " ".join(skill.get("examples", []))])))
            self._texts.extend((agent_id, ex) for ex in skill.get("examples", []))
        self._vectors = None

    def prepare(self) -> None:
        """Embed the cards now (the catalog calls this before swapping the index in)."""
        vectors = self.embed([t for _, t in self._texts]) if self._texts else []
        self._vectors = [(a, _unit(v)) for (a, _), v in zip(self._texts, vectors)]

    def _similarities(self, query: str) -> dict[str, float]:
        if self._vectors is None:
            self.prepare()
        q = _unit(self.embed([query])[0])
        best: dict[str, float] = {}
        for agent_id, v in self._vectors:
            sim = sum(x * y for x, y in zip(q, v))
            best[agent_id] = max(best.get(agent_id, -1.0), sim)
        return best

    def search(self, query: str, limit: int) -> list[tuple[str, float, list[str]]]:
        if not query.strip():
            return []
        keyword = {a: (score, terms) for a, score, terms in self.keyword.search(query, limit)}
        sims = self._similarities(query)
        semantic = sorted((a for a, s in sims.items() if s >= SEMANTIC_MIN), key=lambda a: -sims[a])
        fused: dict[str, float] = {}
        for ranking in (list(keyword), semantic):
            for rank, agent_id in enumerate(ranking):
                fused[agent_id] = fused.get(agent_id, 0.0) + 1 / (RRF_K + rank + 1)
        ranked = sorted(fused, key=lambda a: (-fused[a], -sims.get(a, 0.0)))
        return [(a, round(sims.get(a, 0.0), 3), keyword.get(a, (0, []))[1]) for a in ranked[:limit]]


def make_index(settings: Settings) -> AgentIndex | HybridIndex:
    if settings.search_mode == "keyword":
        return AgentIndex()
    try:
        return HybridIndex(fastembed_embedder())
    except Exception as e:  # missing package, no network for the first download, broken cache
        if settings.search_mode == "hybrid":
            raise
        log.warning("semantic search unavailable, using keyword search: %s", e)
        return AgentIndex()
