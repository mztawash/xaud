"""Tests for the XAUD agent index (xaud_index.py).

Pins the reputation model: work must be earned through verifiable activity
(settlements, attestations, anchored claims, reveals), never declared. A
chatty agent with no work signals is never returned by a query; template
spam collapses into counters instead of separate records.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import xaud_index as xi

DID_A = "did:key:z6Mk" + "A" * 44
DID_B = "did:key:z6Mk" + "B" * 44
DID_C = "did:key:z6Mk" + "C" * 44
NOW = 1_800_000_000


def fresh_state():
    return {"agent_index": {"profiles": {}, "query_times": {}}}


class TemplateHashTests(unittest.TestCase):
    def test_near_duplicates_collapse(self):
        a = "State verification executed on Block #965884. Calculation proof: 9db89ff0"
        b = "State verification executed on Block #965885. Calculation proof: 9ffbf82b"
        self.assertEqual(
            xi.template_hash(a, normalize_numbers=True),
            xi.template_hash(b, normalize_numbers=True),
        )
        self.assertNotEqual(
            xi.template_hash(a, normalize_numbers=False),
            xi.template_hash(b, normalize_numbers=False),
        )

    def test_urls_normalized(self):
        self.assertEqual(
            xi.template_hash("read https://x.example/a/b", True),
            xi.template_hash("read https://y.example/c/d", True),
        )

    def test_meaningful_difference_survives(self):
        self.assertNotEqual(
            xi.template_hash("built a verifier", True),
            xi.template_hash("wrote a paper", True),
        )


class ObserveSignedTests(unittest.TestCase):
    def test_profile_created_and_rooms_counted(self):
        state = fresh_state()
        xi.observe_signed(state, DID_A, "lobby", 1, "hello world", NOW)
        xi.observe_signed(state, DID_A, "technocore", 2, "hello world", NOW + 5)
        profile = state["agent_index"]["profiles"][DID_A]
        self.assertEqual(profile["rooms"], {"lobby": 1, "technocore": 1})
        self.assertEqual(profile["first_seen"], NOW)
        self.assertEqual(profile["last_seen"], NOW + 5)
        self.assertEqual(profile["abbrev"], "z6Mk…" + "A" * 4)

    def test_repeater_flag_on_low_value_repeats(self):
        state = fresh_state()
        for i in range(xi.REPEAT_FLAG_AT):
            xi.observe_signed(
                state, DID_B, "lobby", i, "Alive and well. Still here.", NOW + i,
                low_value=True,
            )
        profile = state["agent_index"]["profiles"][DID_B]
        self.assertIn("repeater", profile["flags"])
        # Repeat count is visible on the last call.
        self.assertEqual(
            xi.observe_signed(state, DID_B, "lobby", 99, "Alive and well. Still here.", NOW + 10, low_value=True),
            xi.REPEAT_FLAG_AT + 1,
        )

    def test_flag_not_set_for_varied_chat(self):
        state = fresh_state()
        for i in range(10):
            xi.observe_signed(state, DID_C, "lobby", i, f"unrelated note {i}", NOW + i)
        profile = state["agent_index"]["profiles"][DID_C]
        self.assertNotIn("repeater", profile["flags"])


class RecordClaimTests(unittest.TestCase):
    CLAIM = "Built a small verifier and published the tool: https://example.com/x"

    def test_first_claim_publishes(self):
        state = fresh_state()
        result = xi.record_claim(
            state, DID_A, "technocore", 7, self.CLAIM,
            tags=["builder"], activity_type="service_job", task="builder", now=NOW,
        )
        self.assertEqual(result["action"], "publish")
        profile = state["agent_index"]["profiles"][DID_A]
        self.assertEqual(profile["claims_published"], 1)
        self.assertIn("builder", profile["tags"])
        self.assertEqual(profile["activity_types"], {"service_job": 1})

    def test_exact_duplicate_suppressed(self):
        state = fresh_state()
        xi.record_claim(state, DID_A, "technocore", 7, self.CLAIM, now=NOW)
        result = xi.record_claim(state, DID_A, "technocore", 99, self.CLAIM, now=NOW + 60)
        self.assertEqual(result["action"], "duplicate")
        profile = state["agent_index"]["profiles"][DID_A]
        self.assertEqual(profile["claims_published"], 1)
        self.assertEqual(profile["claims_duplicates"], 1)

    def test_near_duplicate_with_changed_hash_suppressed(self):
        state = fresh_state()
        one = "State verification executed on Block #965884. Calculation proof: 9db89ff0"
        two = "State verification executed on Block #965885. Calculation proof: 9ffbf82b"
        self.assertEqual(xi.record_claim(state, DID_B, "lobby", 1, one, now=NOW)["action"], "publish")
        self.assertEqual(xi.record_claim(state, DID_B, "lobby", 2, two, now=NOW + 60)["action"], "duplicate")

    def test_republish_after_silence_window(self):
        state = fresh_state()
        xi.record_claim(state, DID_A, "technocore", 7, self.CLAIM, now=NOW)
        result = xi.record_claim(
            state, DID_A, "technocore", 200,
            self.CLAIM, now=NOW + xi.CLAIM_DUP_WINDOW_S + 1,
        )
        self.assertEqual(result["action"], "publish")
        self.assertEqual(state["agent_index"]["profiles"][DID_A]["claims_published"], 2)

    def test_distinct_claims_both_publish(self):
        state = fresh_state()
        xi.record_claim(state, DID_A, "technocore", 1, "built a verifier", now=NOW)
        result = xi.record_claim(state, DID_A, "technocore", 2, "wrote a paper on rails", now=NOW + 60)
        self.assertEqual(result["action"], "publish")


class SettlementAttestationTclkTests(unittest.TestCase):
    def test_settlement_credits_both_sides(self):
        state = fresh_state()
        xi.on_settlement(state, DID_A, DID_B, "1000", "FLOP", "claimed", job_proto="a2a", now=NOW)
        a, b = state["agent_index"]["profiles"][DID_A], state["agent_index"]["profiles"][DID_B]
        self.assertEqual(a["settlements"]["paid"], 1)
        self.assertEqual(b["settlements"]["received"], 1)
        self.assertEqual(b["settlements"]["amount_received"], {"FLOP": 1000})
        self.assertEqual(a["settlements"]["amount_paid"], {"FLOP": 1000})
        self.assertIn("proto:a2a", b["tags"])
        self.assertNotIn("proto:a2a", a["tags"])

    def test_non_claimed_outcome_ignored(self):
        state = fresh_state()
        xi.on_settlement(state, DID_A, DID_B, "1000", "FLOP", "refunded", now=NOW)
        self.assertEqual(state["agent_index"]["profiles"], {})

    def test_attestation_verdicts(self):
        state = fresh_state()
        xi.on_attestation(state, DID_B, "passed", task_type="audit", now=NOW)
        xi.on_attestation(state, DID_B, "failed", task_type="audit", now=NOW + 1)
        profile = state["agent_index"]["profiles"][DID_B]
        self.assertEqual(profile["attestations"], {"passed": 1, "failed": 1, "disputed": 0})
        self.assertIn("audit", profile["tags"])

    def test_tclk_roles_and_proto_tags(self):
        state = fresh_state()
        xi.on_tclk(state, DID_A, "offer", "tclk-offers", 1, now=NOW)
        xi.on_tclk(state, DID_B, "accept", "tclk-offers", 2, proto="a2a", now=NOW)
        xi.on_tclk(state, DID_B, "reveal", "mb-p-tclk-x", 3, proto="a2a", now=NOW)
        b = state["agent_index"]["profiles"][DID_B]
        self.assertEqual(b["tclk"]["accepts"], 1)
        self.assertEqual(b["tclk"]["reveals"], 1)
        a = state["agent_index"]["profiles"][DID_A]
        self.assertEqual(a["tclk"]["offers_posted"], 1)
        # Payer-side offers never grant capability tags.
        self.assertNotIn("proto:a2a", a["tags"])


class CapabilityVocabularyTests(unittest.TestCase):
    """Capability tags mined from verified work contexts (item B)."""

    def test_extracts_capability_words_and_drops_boilerplate(self):
        tags = xi.capability_tags(
            "census | how many offers were live? report the exact value"
        )
        self.assertIn("census", tags)
        self.assertIn("live", tags)
        self.assertNotIn("offer", tags)
        self.assertNotIn("report", tags)
        self.assertNotIn("value", tags)

    def test_bounded_and_deduped(self):
        tags = xi.capability_tags(
            "alpha alpha beta gamma delta epsilon zeta", limit=3
        )
        self.assertEqual(tags, ["alpha", "beta", "gamma"])

    def test_stem_lights_up_plurals_but_keeps_sibilants(self):
        self.assertEqual(xi._stem("reviews"), "review")
        self.assertEqual(xi._stem("analysis"), "analysis")
        self.assertIn("census", xi.capability_tags("census data"))

    def test_settlement_mines_payee_job_context_only(self):
        state = fresh_state()
        xi.on_settlement(
            state, DID_A, DID_B, "1000", "FLOP", "claimed",
            job_proto="a2a",
            job_context="census | how many offers are live",
            now=NOW,
        )
        a = state["agent_index"]["profiles"][DID_A]
        b = state["agent_index"]["profiles"][DID_B]
        self.assertIn("cap:census", b["tags"])
        self.assertNotIn("cap:census", a["tags"])

    def test_claim_mines_capability_tags(self):
        state = fresh_state()
        xi.record_claim(
            state, DID_A, "technocore", 1,
            "Ran a blockrewards review and published the tally",
            now=NOW,
        )
        tags = state["agent_index"]["profiles"][DID_A]["tags"]
        self.assertIn("cap:blockreward", tags)
        self.assertIn("cap:review", tags)
        self.assertIn("cap:tally", tags)

    def test_query_matches_mined_capability_and_ignores_payer(self):
        state = fresh_state()
        xi.on_settlement(
            state, DID_C, DID_B, "1000", "FLOP", "claimed",
            job_context="review | quote the exact value of the quote",
            now=NOW,
        )
        hits = xi.query(state, "find an agent for reviews")
        dids = [hit["did"] for hit in hits]
        self.assertIn(DID_B, dids)
        self.assertNotIn(DID_C, dids)

    def test_capability_vocabulary_bounded_per_agent(self):
        state = fresh_state()
        profile = xi._profile(state, DID_A, NOW)
        words = 0
        limit = xi.MAX_CAPABILITY_TAGS_PER_AGENT * 2
        while words < limit:
            batch = " ".join(
                f"capword{w}"
                for w in range(words, words + xi.CAPABILITY_TAGS_PER_TEXT)
            )
            xi._note_capabilities(profile, batch)
            words += xi.CAPABILITY_TAGS_PER_TEXT
        caps = [
            key for key in profile["tags"]
            if key.startswith(xi.CAPABILITY_TAG_PREFIX)
        ]
        self.assertLessEqual(len(caps), xi.MAX_CAPABILITY_TAGS_PER_AGENT)


class QueryTests(unittest.TestCase):
    def build_state(self):
        state = fresh_state()
        # A hirer, a worker with a verified paid job in proto a2a, an auditor
        # with an attestation but no paid work, and pure chatter.
        xi.on_settlement(state, DID_C, DID_B, "1000", "FLOP", "claimed", job_proto="a2a", now=NOW)
        xi.on_attestation(state, DID_C, "passed", task_type="audit", now=NOW)
        for i in range(50):
            xi.observe_signed(state, DID_A, "lobby", i, f"market talk {i}", NOW + i)
        return state

    def test_paid_worker_ranks_first(self):
        state = self.build_state()
        hits = xi.query(state, "find me an agent for tclk work")
        self.assertEqual(hits[0]["did"], DID_B)
        self.assertIn("1 paid job(s)", hits[0]["reasons"])

    def test_chatter_only_never_returned(self):
        state = self.build_state()
        # DID_A posted 50 signed messages but zero work -> excluded even
        # though it has the highest message volume.
        hits = xi.query(state, "agents")
        dids = [h["did"] for h in hits]
        self.assertNotIn(DID_A, dids)
        self.assertIn(DID_B, dids)

    def test_capability_filter(self):
        state = self.build_state()
        hits = xi.query(state, "audit agent")
        dids = [h["did"] for h in hits]
        self.assertIn(DID_C, dids)
        self.assertNotIn(DID_B, dids)

    def test_repeater_penalized(self):
        state = fresh_state()
        xi.on_settlement(state, DID_A, DID_B, "500", "FLOP", "claimed", job_proto="a2a", now=NOW)
        for i in range(xi.REPEAT_FLAG_AT):
            xi.observe_signed(state, DID_A, "lobby", i, "Alive and well today.", NOW + i, low_value=True)
        hits = xi.query(state, "agents")
        self.assertEqual(hits[0]["did"], DID_B)

    def test_candidate_line_names_the_full_did(self):
        # An abbreviated z6Mk…xxxx cannot be hired; the answer must name the DID.
        state = self.build_state()
        hits = xi.query(state, "find me an agent for tclk work")
        line = xi.format_candidate(hits[0], 1)
        self.assertIn(DID_B, line)
        self.assertNotIn("…", line)

    def test_index_summary(self):
        state = self.build_state()
        summary = xi.index_summary(state)
        self.assertEqual(summary["agents_tracked"], 3)
        self.assertEqual(summary["agents_with_paid_work"], 1)
        self.assertEqual(summary["agents_with_attestations"], 1)
        self.assertEqual(summary["agents_with_claims"], 0)

    def test_query_exposes_freshness_signals_and_evidence(self):
        state = fresh_state()
        xi.on_settlement(
            state, DID_C, DID_B, "1000", "FLOP", "claimed",
            job_proto="a2a", job_context="audit review", rail="paper", now=NOW,
        )
        xi.on_tclk(state, DID_B, "reveal", "mb-p-tclk-test", 42, proto="a2a", now=NOW)
        hit = xi.query(state, "audit", now=NOW + 10)[0]
        self.assertEqual(hit["age_s"], 10)
        self.assertEqual(hit["signals"]["claimed_jobs"], 1)
        self.assertIn("audit", hit["tags"])
        self.assertEqual(hit["evidence_refs"], ["mb-p-tclk-test:42"])

    def test_query_filters_by_score_and_freshness(self):
        state = fresh_state()
        xi.on_settlement(state, DID_A, DID_B, "1000", "FLOP", "claimed", now=NOW)
        xi.on_attestation(state, DID_C, "passed", task_type="audit", now=NOW - 100)
        self.assertEqual(
            [hit["did"] for hit in xi.query(state, "agents", min_score=30, now=NOW)],
            [DID_B],
        )
        self.assertEqual(
            [hit["did"] for hit in xi.query(state, "audit", since=NOW - 10, now=NOW)],
            [],
        )

    def test_summary_tracks_settlement_rail_and_outcome(self):
        state = fresh_state()
        xi.on_settlement(state, DID_A, DID_B, "100", "FLOP", "refunded", rail="paper", now=NOW)
        summary = xi.index_summary(state)
        self.assertEqual(summary["settlement_outcomes"], {"paper:refunded": 1})
        self.assertEqual(summary["agents_tracked"], 0)


class CooldownTests(unittest.TestCase):
    def test_same_query_blocked_within_window(self):
        state = fresh_state()
        self.assertTrue(xi.query_allowed(state, "xaud", "find an auditor", NOW))
        self.assertFalse(xi.query_allowed(state, "xaud", "find an auditor", NOW + 5))
        self.assertTrue(xi.query_allowed(state, "xaud", "find an auditor", NOW + xi.QUERY_COOLDOWN_S))


if __name__ == "__main__":
    unittest.main()
