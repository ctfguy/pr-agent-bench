from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from advisory_miner.runtime import (
    RateBudget,
    ResponseCache,
    current_metrics,
    reset_metrics,
)


class ResponseCacheTests(unittest.TestCase):
    def test_set_and_get_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = ResponseCache(Path(tmp), "github")
            key = ResponseCache.key("GET", "/repos/foo/bar", {"per_page": 100})
            self.assertIsNone(cache.get(key))
            cache.set(key, {"data": [1, 2, 3]})
            self.assertEqual(cache.get(key), {"data": [1, 2, 3]})

    def test_key_is_deterministic_across_param_order(self):
        a = ResponseCache.key("GET", "/x", {"a": 1, "b": 2})
        b = ResponseCache.key("GET", "/x", {"b": 2, "a": 1})
        self.assertEqual(a, b)

    def test_key_changes_with_value(self):
        a = ResponseCache.key("GET", "/x", {"a": 1})
        b = ResponseCache.key("GET", "/x", {"a": 2})
        self.assertNotEqual(a, b)


class MetricsTests(unittest.TestCase):
    def test_reset_and_current_thread_local(self):
        reset_metrics()
        current_metrics().github_calls += 3
        self.assertEqual(current_metrics().github_calls, 3)

        outcomes: list[int] = []

        def worker():
            reset_metrics()
            current_metrics().github_calls += 7
            outcomes.append(current_metrics().github_calls)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        self.assertEqual(outcomes, [7])
        # Main thread's metrics remain isolated.
        self.assertEqual(current_metrics().github_calls, 3)


class RateBudgetTests(unittest.TestCase):
    def test_acquire_decrements_tokens(self):
        budget = RateBudget(per_hour=3)
        budget.acquire()
        budget.acquire()
        snapshot = budget.snapshot()
        self.assertEqual(snapshot["tokens_remaining"], 1)

    def test_update_from_headers_overrides_tokens(self):
        budget = RateBudget(per_hour=100)
        budget.acquire()
        budget.update_from_headers({"X-RateLimit-Remaining": "12", "X-RateLimit-Reset": str(int(time.time()) + 60)})
        self.assertEqual(budget.snapshot()["tokens_remaining"], 12)

    def test_acquire_blocks_then_releases_after_window_reset(self):
        budget = RateBudget(per_hour=1)
        budget.acquire()
        # Force window reset in the immediate future.
        with budget._cv:  # noqa: SLF001 - exercising window behavior
            budget._reset_at = time.time() + 0.05  # noqa: SLF001
        budget.acquire(timeout=2.0)
        # After the second acquire the bucket refilled then took one token; >=0 expected.
        self.assertGreaterEqual(budget.snapshot()["tokens_remaining"], 0)


if __name__ == "__main__":
    unittest.main()
