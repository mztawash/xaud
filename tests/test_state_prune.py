"""State pruning: contracts and indexes must stay bounded.

A tclk transcript is the bulk of the state file, and deals settle or expire
within minutes. Without a retention policy the file grows without bound
(observed: 26,403 contracts, ~81 MB, 28 resolved) and every batched write
pays for it. These tests pin the P4 retention policy.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import state


def contract(updated, **fields):
    record = {"updated_at": updated, "transcript": [{"x": 1}], "events": []}
    record.update(fields)
    return record


class PruneContractTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_000_000.0

    def test_legacy_contract_without_timestamp_is_evicted(self):
        st = state.new_state()
        cid = "0x" + "1" * 64
        st["tclk_contracts"][cid] = {"transcript": [{"x": 1}], "events": []}
        state.prune_state(st, now=self.now)
        self.assertNotIn(cid, st["tclk_contracts"])

    def test_fresh_kept_and_stale_evicted(self):
        st = state.new_state()
        fresh, stale = "0x" + "1" * 64, "0x" + "2" * 64
        st["tclk_contracts"][fresh] = contract(self.now - 10)
        st["tclk_contracts"][stale] = contract(
            self.now - state.CONTRACT_TTL_S - 1
        )
        state.prune_state(st, now=self.now)
        self.assertIn(fresh, st["tclk_contracts"])
        self.assertNotIn(stale, st["tclk_contracts"])

    def test_resolved_contract_collapses_to_tombstone(self):
        st = state.new_state()
        cid = "0x" + "3" * 64
        st["tclk_contracts"][cid] = contract(
            self.now,
            candidate_posted=True,
            transcript=[{"big": "x" * 5000}],
            payee_did="did:key:z",
        )
        state.prune_state(st, now=self.now)
        self.assertEqual(
            st["tclk_contracts"][cid],
            {"candidate_posted": True, "updated_at": self.now},
        )

    def test_tombstone_is_never_aged_out(self):
        st = state.new_state()
        cid = "0x" + "4" * 64
        st["tclk_contracts"][cid] = {
            "candidate_posted": True,
            "updated_at": self.now - 10**9,
        }
        state.prune_state(st, now=self.now)
        self.assertTrue(st["tclk_contracts"][cid]["candidate_posted"])

    def test_hard_cap_evicts_oldest(self):
        st = state.new_state()
        for i in range(state.CONTRACT_MAX + 10):
            st["tclk_contracts"][f"0x{i:064x}"] = contract(self.now - i)
        summary = state.prune_state(st, now=self.now)
        self.assertEqual(len(st["tclk_contracts"]), state.CONTRACT_MAX)
        self.assertGreaterEqual(summary["contracts_removed"], 10)
        self.assertIn(f"0x{0:064x}", st["tclk_contracts"])
        self.assertNotIn(f"0x{state.CONTRACT_MAX + 9:064x}", st["tclk_contracts"])

    def test_did_index_capped(self):
        st = state.new_state()
        for i in range(state.DID_INDEX_MAX + 10):
            st["did_index"][f"k{i}"] = f"did:key:{i}"
        state.prune_state(st, now=self.now)
        self.assertEqual(len(st["did_index"]), state.DID_INDEX_MAX)
        self.assertNotIn("k0", st["did_index"])

    def test_prune_is_idempotent(self):
        st = state.new_state()
        st["tclk_contracts"]["0x" + "5" * 64] = contract(self.now)
        state.prune_state(st, now=self.now)
        second = state.prune_state(st, now=self.now)
        self.assertEqual(second["contracts_removed"], 0)
        self.assertEqual(second["contracts_collapsed"], 0)


if __name__ == "__main__":
    unittest.main()
