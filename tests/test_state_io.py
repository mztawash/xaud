"""Tests for state I/O: process cache, batched writes, compact encoding.

The live agent's ingestion was bounded by state I/O, not by the network:
reading and pretty-printing the whole 2 MB state per message cost ~100 ms +
~220 ms, capping throughput below the rate of a live room. These tests pin
the fix — a path-keyed process cache and one atomic write per batch.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import state


class StateIoTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "agent_state.json"
        patcher = mock.patch.object(state, "STATE_FILE", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Keep module-global batch/cache state from leaking between tests.
        self.addCleanup(setattr, state, "_STATE_CACHE", None)
        self.addCleanup(setattr, state, "_CACHE_PATH", None)
        self.addCleanup(setattr, state, "_BATCH_DEPTH", 0)

    def test_save_then_load_roundtrips(self):
        st = state.new_state()
        st["room_cursors"]["lobby"] = 42
        state.save_state(st)
        self.assertTrue(self.path.exists())
        self.assertEqual(state.load_state()["room_cursors"]["lobby"], 42)

    def test_load_is_cached_and_shared(self):
        st = state.load_state()
        st["stats"]["messages_seen"] = 7
        # The same object comes back, so a mutation is visible without a write.
        self.assertIs(state.load_state(), st)
        self.assertEqual(state.load_state()["stats"]["messages_seen"], 7)

    def test_cache_is_keyed_by_state_file_path(self):
        first = state.load_state()
        first["stats"]["messages_seen"] = 11
        other = Path(self._tmp.name) / "other_state.json"
        with mock.patch.object(state, "STATE_FILE", other):
            fresh = state.load_state()
        self.assertIsNot(fresh, first)
        self.assertEqual(fresh["stats"]["messages_seen"], 0)

    def test_batch_defers_writes_and_flushes_once(self):
        st = state.load_state()
        writes = []
        with mock.patch.object(
            state, "_write_state", side_effect=lambda s: writes.append(s)
        ):
            state.begin_batch()
            for _ in range(50):
                st["stats"]["messages_seen"] += 1
                state.save_state(st)
            self.assertEqual(writes, [])  # nothing hit disk mid-batch
            state.end_batch()
        self.assertEqual(len(writes), 1)

    def test_batched_increments_persist_after_flush(self):
        st = state.load_state()
        state.begin_batch()
        st["stats"]["messages_seen"] += 5
        state.save_state(st)
        state.end_batch()
        on_disk = json.loads(self.path.read_text())
        self.assertEqual(on_disk["stats"]["messages_seen"], 5)

    def test_state_file_is_compact(self):
        state.save_state(state.new_state())
        raw = self.path.read_text()
        self.assertNotIn("\n  ", raw)  # not indent=2 pretty-printed
        self.assertEqual(json.loads(raw)["stats"]["queries_answered"], 0)


if __name__ == "__main__":
    unittest.main()
