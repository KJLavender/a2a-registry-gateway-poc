"""Search behavior that needs no running stack."""
from __future__ import annotations

import unittest

from poc.search import HybridIndex

CARD = {"name": "IT 服務台", "description": "VPN 與帳號問題",
        "skills": [{"id": "vpn", "name": "VPN 連線", "description": "VPN 連不上", "tags": ["VPN"],
                    "examples": ["在家連不上 VPN"]}]}
OTHER = {"name": "費用簽核", "description": "報銷", "skills": [{"id": "exp", "name": "報銷", "description": "差旅費",
                                                          "tags": ["費用"], "examples": ["申請差旅費"]}]}


class HybridFallback(unittest.TestCase):
    def test_embedding_errors_fall_back_to_keywords(self):
        def broken(texts, remember=False):
            raise RuntimeError("model files missing")
        index = HybridIndex(broken)
        index.add("it-helpdesk", CARD)
        index.add("expense", OTHER)  # BM25 needs more than one document for a useful idf
        index.prepare()  # must not raise: the catalog stays usable
        self.assertEqual([hit[0] for hit in index.search("VPN 連不上", 3)], ["it-helpdesk"])

    def test_query_errors_fall_back_to_keywords(self):
        calls = []

        def flaky(texts, remember=False):
            calls.append(remember)
            if not remember:
                raise RuntimeError("inference failed")
            return [[1.0, 0.0] for _ in texts]
        index = HybridIndex(flaky)
        index.add("it-helpdesk", CARD)
        index.add("expense", OTHER)  # BM25 needs more than one document for a useful idf
        index.prepare()
        self.assertEqual([hit[0] for hit in index.search("VPN 連不上", 3)], ["it-helpdesk"])
        self.assertIn(False, calls)


if __name__ == "__main__":
    unittest.main()
