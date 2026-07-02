from __future__ import annotations

import unittest

from advisory_miner.agents.langgraph_workflow import build_langgraph_advisory_graph


class LangGraphWorkflowTests(unittest.TestCase):
    def test_langgraph_builds_and_runs(self):
        class Analyzer:
            def analyze(self, advisory, skip_git=False):
                return {"ghsa_id": advisory["ghsa_id"], "skip_git": skip_git}

        graph = build_langgraph_advisory_graph(Analyzer())
        result = graph.invoke({"advisory": {"ghsa_id": "GHSA-test-test-test"}, "skip_git": True})
        self.assertEqual(result["result"]["ghsa_id"], "GHSA-test-test-test")
        self.assertTrue(result["result"]["skip_git"])


if __name__ == "__main__":
    unittest.main()
