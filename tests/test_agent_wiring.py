"""Integration tests for xaud_records wiring inside agent.py.

These drive the real observer functions (no network) by:
  - redirecting the state file to a temp path,
  - stubbing agent.signed_post to capture the published frame text,
  - signing every transport record with real Ed25519 keys (as tclk/1 does).

Run from the repository root:
    .venv/bin/python -m unittest discover -s tests
"""

import hashlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import agent
import state
import xaud_records as xr
from sign import did_of, load_key, signature
from tclk_observer import deal_room, fold_tclk_lifecycle
from xaud_attestation import build_attestation_frame

OFFER_ID = "0x" + "1" * 64
CONTRACT = "0x" + "2" * 64
DEAL_ROOM = deal_room(CONTRACT)


def canonical_tclk(frame):
    return "tclk1 " + json.dumps(frame, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def signed_record(room, seq, frame, key):
    text = canonical_tclk(frame)
    nonce = str(1000 + seq)
    return {
        "room": room,
        "seq": seq,
        "ts": "2026-09-07T12:00:00Z",
        "from": frame["from"],
        "nonce": nonce,
        "text": text,
        "sig": signature(key, f"{room}|{nonce}|{text}"),
    }


def full_claimed_transcript(terminal="claimed", job=None):
    """Return (frames, records, payer, payee, secret, statement).

    terminal: "claimed" (reveal + receipt), "reveal-only" (no receipt),
    "refunded" (refund instead of reveal), "cancelled" (accepted then
    cancelled in tclk-offers), or "proposed-cancel" (offer cancelled before
    any accept). ``job`` overrides the offer's job block (e.g. to add a
    ``context`` the capability vocabulary should be mined from).
    """
    payer_key, _ = load_key("wire-payer")
    payee_key, _ = load_key("wire-payee")
    payer = did_of(payer_key)
    payee = did_of(payee_key)
    secret = bytes(range(32))
    statement = "0x" + hashlib.sha256(secret).hexdigest()

    frames = [
        ("tclk-offers", 1, {
            "amount": "1000000",
            "asset": "FLOP",
            "claimByMs": 1790000000000,
            "expiresMs": 1789990000000,
            "from": payer,
            "id": OFFER_ID,
            "job": job if job is not None else {"proto": "a2a", "id": "task-3f"},
            "lock": "hash",
            "nonce": "a1",
            "rails": ["paper"],
            "refundAfterMs": 1000,
            "role": "payer",
            "type": "offer",
        }, payer_key),
        ("tclk-offers", 2, {
            "contract": CONTRACT,
            "from": payee,
            "nonce": "a2",
            "ref": OFFER_ID,
            "statement": statement,
            "type": "accept",
        }, payee_key),
    ]
    if terminal == "cancelled":
        # tclk/1 allows cancels only while proposed or accepted, so there is
        # no lock frame on this path.
        frames.append(("tclk-offers", 3, {
            "contract": CONTRACT,
            "from": payer,
            "reason": "scope changed",
            "type": "cancel",
        }, payer_key))
    elif terminal == "proposed-cancel":
        # Offer cancelled before any accept: frames only in tclk-offers.
        frames = [frames[0], ("tclk-offers", 2, {
            "contract": CONTRACT,
            "from": payer,
            "reason": "changed my mind",
            "type": "cancel",
        }, payer_key)]
    else:
        frames.append((DEAL_ROOM, 3, {
            "contract": CONTRACT,
            "from": payer,
            "rail": "paper",
            "ref": "paper-escrow-1",
            "type": "lock",
        }, payer_key))
    if terminal == "refunded":
        frames.append((DEAL_ROOM, 4, {
            "contract": CONTRACT,
            "from": payer,
            "ref": "paper-escrow-1",
            "type": "refund",
        }, payer_key))
    elif terminal in ("reveal-only", "claimed"):
        reveal = (DEAL_ROOM, 4, {
            "contract": CONTRACT,
            "from": payee,
            "ref": "paper-escrow-1",
            "secret": "0x" + secret.hex(),
            "type": "reveal",
        }, payee_key)
        frames.append(reveal)
        if terminal == "claimed":
            frames.append((DEAL_ROOM, 5, {
                "contract": CONTRACT,
                "from": payer,
                "outcome": "claimed",
                "rail": "paper",
                "type": "receipt",
            }, payer_key))
    records = [signed_record(room, seq, frame, key) for (room, seq, frame, key) in frames]
    return frames, records, payer, payee, secret, statement


class TempStateTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch.object(state, "STATE_FILE", Path(self._tmp.name) / "agent_state.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.posted = []
        post_patcher = mock.patch.object(agent, "signed_post", side_effect=lambda room, text: self.posted.append((room, text)))
        post_patcher.start()
        self.addCleanup(post_patcher.stop)
        # KV mirror: capture writes, never shell out to sign.py or hit the
        # network. The mirror flow itself (nonce, wrapper, call sites) runs.
        self.mirrors = []
        kv_set_patcher = mock.patch.object(
            agent, "set_kv_note",
            side_effect=lambda ns, key, value: self.mirrors.append((ns, key, value)) or "ok",
        )
        kv_set_patcher.start()
        self.addCleanup(kv_set_patcher.stop)
        kv_sign_patcher = mock.patch.object(
            agent, "sign_note_canonical",
            side_effect=lambda ns, key, nonce, value: ("did:key:z6Mk" + "9" * 44, "m" * 86),
        )
        kv_sign_patcher.start()
        self.addCleanup(kv_sign_patcher.stop)

    def latest_post(self):
        self.assertTrue(self.posted, "nothing was posted")
        return self.posted[-1]


class TclkSettlementWiringTests(TempStateTestCase):
    def test_completed_claimed_deal_publishes_a_canonical_settlement(self):
        frames, records, payer, payee, secret, statement = full_claimed_transcript()

        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)

        room, text = self.latest_post()
        self.assertEqual(room, "xaud")
        self.assertTrue(text.startswith("xaud1 "))
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["type"], "settlement")
        self.assertEqual(frame["contract"], CONTRACT)
        self.assertEqual(frame["payer"], payer)
        self.assertEqual(frame["payee"], payee)
        self.assertEqual(frame["amount"], "1000000")
        self.assertEqual(frame["asset"], "FLOP")
        self.assertEqual(frame["outcome"], "claimed")
        self.assertEqual(frame["status"], "terms_verified")
        self.assertEqual(frame["verified_by"], "transcript")
        self.assertEqual(frame["rail"], "paper")
        self.assertEqual(frame["job"], {"proto": "a2a", "id": "task-3f"})
        self.assertEqual(frame["evidence"]["room"], DEAL_ROOM)
        self.assertEqual(frame["evidence"]["seq"], 4)  # the reveal
        self.assertEqual(frame["evidence"]["offer_room"], "tclk-offers")
        self.assertEqual(frame["evidence"]["offer_seq"], 1)

        persisted = state.load_state()
        self.assertEqual(
            persisted["stats"].get("tclk_candidates_recorded"), 1,
        )
        self.assertTrue(persisted["tclk_contracts"][CONTRACT]["candidate_posted"])

    def test_settlement_mines_job_context_into_the_agent_index(self):
        job = {
            "proto": "a2a",
            "id": "task-9",
            "context": "census | how many offers are live",
        }
        frames, records, payer, payee, _secret, _statement = full_claimed_transcript(job=job)
        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)

        persisted = state.load_state()
        profiles = persisted["agent_index"]["profiles"]
        self.assertIn("cap:census", profiles[payee]["tags"])
        # The hirer bought the capability; it did not earn it.
        self.assertNotIn("cap:census", profiles[payer]["tags"])

    def test_deal_run_entirely_in_offers_room_settles(self):
        # The venue refuses to create new deal rooms (its room cap), so live deals
        # run their lock/reveal/receipt in tclk-offers. The fold must not reject
        # them: refusing made XAUD blind to the deals that actually complete.
        frames, records, payer, payee, _secret, _statement = full_claimed_transcript()
        for (room, seq, frame, key) in frames:
            where = "tclk-offers" if room == DEAL_ROOM else room
            record = signed_record(where, seq, frame, key)
            agent.observe_tclk_frame(where, seq, frame_text_for(record), record)

        room, text = self.latest_post()
        self.assertEqual(room, "xaud")
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["type"], "settlement")
        self.assertEqual(frame["outcome"], "claimed")
        self.assertEqual(frame["status"], "terms_verified")
        self.assertEqual(frame["payee"], payee)
        self.assertEqual(frame["payer"], payer)

    def test_observed_contract_records_a_prune_timestamp(self):
        # prune_state ages contracts by updated_at, so every touch must stamp it.
        frames, records, *_ = full_claimed_transcript()
        room, seq, frame, _key = frames[0]
        agent.observe_tclk_frame(room, seq, frame_text_for(records[0]), records[0])
        record = state.load_state()["tclk_contracts"][frame["id"]]
        self.assertIsInstance(record["updated_at"], float)

    def test_missing_offer_publishes_outcome_tier(self):
        # The offer aged out of the firehose before XAUD started; only accept,
        # lock and reveal remain. The lifecycle is still provable, so publish
        # the honest partial tier instead of dropping the deal.
        frames, records, payer, payee, _secret, _statement = full_claimed_transcript()
        for (room, seq, frame, _key), record in zip(frames[1:], records[1:]):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)

        room, text = self.latest_post()
        self.assertEqual(room, "xaud")
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["type"], "settlement")
        self.assertEqual(frame["status"], "outcome_verified")
        self.assertEqual(frame["outcome"], "claimed")
        self.assertEqual(frame["payer"], payer)
        self.assertEqual(frame["payee"], payee)
        self.assertNotIn("amount", frame)
        self.assertNotIn("asset", frame)
        persisted = state.load_state()
        self.assertTrue(persisted["tclk_contracts"][CONTRACT]["candidate_posted"])
        self.assertEqual(
            persisted["xaud_ledger"][CONTRACT]["tier"], "outcome_verified"
        )

    def test_missing_offer_without_a_payer_is_not_published(self):
        # accepted-then-cancelled with no lock: the payer was never observed,
        # so a settlement cannot name both parties. Publish nothing.
        frames, records, *_ = full_claimed_transcript(terminal="cancelled")
        for (room, seq, frame, _key), record in zip(frames[1:], records[1:]):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)
        self.assertFalse(self.posted)

    def test_scrambled_transcript_still_settles(self):
        # Observation order is not trustworthy: XAUD can read a derived deal
        # room before the offer/accept it belongs to. The fold must still
        # settle once the transcript is complete.
        _frames, records, payer, payee, _secret, _statement = full_claimed_transcript()
        by_type = {}
        for record in records:
            body = json.loads(record["text"][len("tclk1 "):])
            by_type[body["type"]] = record
        scrambled = [
            by_type["reveal"], by_type["lock"], by_type["receipt"],
            by_type["offer"], by_type["accept"],
        ]
        for record in scrambled:
            agent.observe_tclk_frame(
                record["room"], record["seq"], frame_text_for(record), record
            )

        room, text = self.latest_post()
        self.assertEqual(room, "xaud")
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["type"], "settlement")
        self.assertEqual(frame["outcome"], "claimed")
        self.assertEqual(frame["payee"], payee)
        self.assertEqual(frame["payer"], payer)
        persisted = state.load_state()
        self.assertTrue(persisted["tclk_contracts"][CONTRACT]["candidate_posted"])
        self.assertEqual(persisted["stats"].get("tclk_candidates_recorded"), 1)

    def test_a_second_receipt_does_not_double_post(self):
        frames, records, *_ = full_claimed_transcript()
        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)
        # Re-observe the same receipt again.
        agent.observe_tclk_frame(DEAL_ROOM, 5, frame_text_for(records[-1]), records[-1])
        self.assertEqual(len(self.posted), 1)

    def test_tampered_transcript_publishes_nothing(self):
        frames, records, payer, payee, secret, statement = full_claimed_transcript()
        # Break the lock step signature before feeding the receipt.
        bad_lock = dict(records[2])
        bad_lock["sig"] = bad_lock["sig"][:-4] + "AAAA"
        records[2] = bad_lock

        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)

        self.assertEqual(self.posted, [])
        persisted = state.load_state()
        self.assertEqual(
            persisted.get("stats", {}).get("tclk_candidates_recorded", 0),
            0,
        )


def signed_claim(room, seq, text, key):
    """Build a transport-signed chat message as the live feed would return it."""
    nonce = str(3000 + seq)
    return {
        "from": did_of(key),
        "nonce": nonce,
        "text": text,
        "sig": signature(key, f"{room}|{nonce}|{text}"),
    }


def seed_tracked_contract():
    """Make CONTRACT present but not terminal in the temp state file."""
    st = state.load_state()
    st.setdefault("tclk_contracts", {})[CONTRACT] = {
        "events": [{"type": "accept", "room": "tclk-offers", "seq": 2}],
        "transcript": [],
    }
    state.save_state(st)


class ContributionWiringTests(TempStateTestCase):
    """Phase B: prose claims are recorded only when attributable + anchored."""

    def test_anchored_tracked_contract_publishes_an_identified_observation(self):
        worker_key, _ = load_key("claim-worker")
        worker = did_of(worker_key)
        seed_tracked_contract()

        text = f"Built the translation tool for job {CONTRACT} and finished it."
        payload = agent.record_contribution_if_relevant(
            "ai",
            77,
            text,
            worker,
            signed_claim("ai", 77, text, worker_key),
        )
        self.assertIsNotNone(payload)
        self.assertEqual(payload["anchor_kind"], "contract_tracked")
        self.assertEqual(payload["anchor_detail"], CONTRACT)

        room, posted_text = self.latest_post()
        self.assertEqual(room, "xaud")
        frame = xr.parse_xaud_record(posted_text)
        self.assertEqual(frame["type"], "observation")
        self.assertEqual(frame["agent_did"], worker)
        self.assertEqual(frame["identity_status"], "identified")
        self.assertEqual(frame["status"], "observed")
        self.assertEqual(frame["evidence"], {"room": "ai", "seq": 77})
        self.assertEqual(frame["task"], "builder")
        self.assertEqual(frame["score"], payload["score"])
        # The subject's exact words are preserved verbatim as the summary.
        self.assertIn("Built the translation tool", frame["summary"])

    def test_verified_ledger_contract_is_not_reposted_as_an_observation(self):
        frames, records, *_ = full_claimed_transcript()
        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)
        self.assertEqual(len(self.posted), 1)  # the settlement itself

        worker_key, _ = load_key("claim-worker")
        worker = did_of(worker_key)
        text = f"Completed the work for {CONTRACT}; happy to share details."
        payload = agent.record_contribution_if_relevant(
            "lobby",
            9,
            text,
            worker,
            signed_claim("lobby", 9, text, worker_key),
        )
        self.assertIsNone(payload)
        self.assertEqual(len(self.posted), 1)  # nothing extra was posted

    def test_signed_claim_without_anchor_is_skipped(self):
        worker_key, _ = load_key("claim-worker")
        worker = did_of(worker_key)
        text = "Built a verifier and published the test result at https://example.test/verifier."
        payload = agent.record_contribution_if_relevant(
            "lobby",
            10,
            text,
            worker,
            signed_claim("lobby", 10, text, worker_key),
        )
        self.assertIsNone(payload)
        self.assertEqual(self.posted, [])

    def test_unsigned_message_is_skipped_even_with_an_anchor(self):
        worker_key, _ = load_key("claim-worker")
        worker = did_of(worker_key)
        seed_tracked_contract()
        text = f"Built the translation tool for job {CONTRACT} and finished it."
        message = {"from": worker, "nonce": "1", "text": text}  # no sig
        payload = agent.record_contribution_if_relevant(
            "ai",
            11,
            text,
            worker,
            message,
        )
        self.assertIsNone(payload)
        self.assertEqual(self.posted, [])

    def test_message_ref_anchor_publishes(self):
        worker_key, _ = load_key("claim-worker")
        worker = did_of(worker_key)

        earlier = signed_claim("lobby", 5, "Verifier build complete; details in my log.", worker_key)
        st = state.load_state()
        self.assertTrue(agent.remember_evidence(st, "lobby", 5, earlier))
        state.save_state(st)

        text = "Built and shipped the verifier; see room:lobby seq:5"
        payload = agent.record_contribution_if_relevant(
            "ai",
            40,
            text,
            worker,
            signed_claim("ai", 40, text, worker_key),
        )
        self.assertIsNotNone(payload)
        self.assertEqual(payload["anchor_kind"], "message_ref")
        self.assertEqual(payload["anchor_detail"], "lobby:5")

    def test_low_value_presence_is_not_recorded(self):
        self.assertIsNone(
            agent.record_contribution_if_relevant(
                "lobby",
                1,
                "Another day, another check-in. The agentic economy narrative is really picking up.",
                "did:key:z6Mk" + "6" * 44,
            )
        )
        self.assertEqual(self.posted, [])


class EvidenceLogTests(TempStateTestCase):
    def test_only_transport_verified_full_did_messages_are_remembered(self):
        key, _ = load_key("log-agent")
        did = did_of(key)
        st = state.load_state()

        unsigned = {"from": did, "nonce": "1", "text": "hello"}
        self.assertFalse(agent.remember_evidence(st, "lobby", 1, unsigned))

        abbreviated = {"from": "z6Mk…51PD", "nonce": "2", "text": "hi"}
        self.assertFalse(agent.remember_evidence(st, "lobby", 2, abbreviated))

        signed = signed_claim("lobby", 3, "Verified message.", key)
        self.assertTrue(agent.remember_evidence(st, "lobby", 3, signed))
        entry = st["evidence_log"]["lobby:3"]
        self.assertEqual(entry["from"], did)
        self.assertTrue(entry["verified"])

    def test_evidence_log_is_bounded(self):
        key, _ = load_key("log-agent")
        st = state.load_state()
        st["evidence_log"] = {
            f"r:{i}": {"from": "x", "verified": True}
            for i in range(agent.EVIDENCE_LOG_LIMIT)
        }
        signed = signed_claim("new-room", 1, "One more.", key)
        self.assertTrue(agent.remember_evidence(st, "new-room", 1, signed))
        self.assertLessEqual(len(st["evidence_log"]), agent.EVIDENCE_LOG_LIMIT)
        self.assertNotIn("r:0", st["evidence_log"])
        self.assertIn("new-room:1", st["evidence_log"])


class KvMirrorTests(TempStateTestCase):
    """Phase C: canonical frames are mirrored to deterministic KV notes."""

    NS_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
    MIRROR_DID = "did:key:z6Mk" + "9" * 44

    def assert_valid_note_location(self, ns, key):
        self.assertRegex(ns, self.NS_PATTERN)
        self.assertRegex(key, self.NS_PATTERN)
        self.assertLessEqual(len(ns), 48)
        self.assertLessEqual(len(key), 48)

    def test_note_locations_are_deterministic_short_and_sharded(self):
        ns, key = agent.settlement_note_location(CONTRACT)
        self.assertEqual((ns, key), agent.settlement_note_location(CONTRACT))
        self.assertTrue(ns.startswith("xaud-s-"))
        self.assert_valid_note_location(ns, key)

        ns2, key2 = agent.settlement_note_location("0x" + "3" * 64)
        self.assert_valid_note_location(ns2, key2)
        self.assertTrue(ns2.startswith("xaud-s-"))
        self.assertNotEqual((ns, key), (ns2, key2))

        on, ok_ = agent.observation_note_location("ai", 77)
        self.assertEqual((on, ok_), agent.observation_note_location("ai", 77))
        self.assertTrue(on.startswith("xaud-o-"))
        self.assert_valid_note_location(on, ok_)
        self.assertNotEqual((on, ok_), (ns, key))  # kinds never collide

    def test_claimed_deal_mirrors_a_tamper_evident_settlement_note(self):
        frames, records, *_ = full_claimed_transcript()
        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)

        self.assertEqual(len(self.mirrors), 1)
        ns, key, wrapper_text = self.mirrors[0]
        self.assertEqual((ns, key), agent.settlement_note_location(CONTRACT))

        wrapper = json.loads(wrapper_text)
        # The wrapper is ASCII single-line and self-authenticating.
        self.assertTrue(all(ord(ch) < 128 for ch in wrapper_text))
        self.assertEqual(wrapper["d"], self.MIRROR_DID)
        self.assertEqual(len(wrapper["s"]), 86)
        # The mirrored frame is byte-identical to the broadcast settlement.
        self.assertEqual(wrapper["f"], self.posted[-1][1])
        frame = xr.parse_xaud_record(wrapper["f"])
        self.assertEqual(frame["contract"], CONTRACT)

        # The mirror used a fresh nonce from state, persisted by the caller.
        self.assertGreater(int(wrapper["n"]), 0)
        self.assertGreater(state.load_state()["last_nonce"], 0)

    def test_anchored_observation_mirrors_a_note_derived_from_its_evidence(self):
        worker_key, _ = load_key("claim-worker")
        worker = did_of(worker_key)
        seed_tracked_contract()

        text = f"Built the translation tool for job {CONTRACT} and finished it."
        payload = agent.record_contribution_if_relevant(
            "ai", 77, text, worker, signed_claim("ai", 77, text, worker_key),
        )
        self.assertIsNotNone(payload)

        self.assertEqual(len(self.mirrors), 1)
        ns, key, wrapper_text = self.mirrors[0]
        self.assertEqual((ns, key), agent.observation_note_location("ai", 77))
        wrapper = json.loads(wrapper_text)
        self.assertEqual(wrapper["f"], self.posted[-1][1])
        frame = xr.parse_xaud_record(wrapper["f"])
        self.assertEqual(frame["evidence"], {"room": "ai", "seq": 77})

    def test_mirror_failure_never_aborts_the_settlement_post(self):
        with mock.patch.object(agent, "sign_note_canonical", side_effect=RuntimeError("signer down")):
            frames, records, *_ = full_claimed_transcript()
            for (room, seq, frame, _key), record in zip(frames, records):
                agent.observe_tclk_frame(room, seq, frame_text_for(record), record)
        # The settlement was still posted; only the mirror write failed.
        self.assertEqual(len(self.posted), 1)
        self.assertEqual(self.mirrors, [])
        self.assertTrue(state.load_state()["tclk_contracts"][CONTRACT]["candidate_posted"])

    def test_mirror_failure_never_aborts_the_observation_post(self):
        worker_key, _ = load_key("claim-worker")
        worker = did_of(worker_key)
        seed_tracked_contract()
        text = f"Built the translation tool for job {CONTRACT} and finished it."
        with mock.patch.object(agent, "sign_note_canonical", side_effect=RuntimeError("signer down")):
            payload = agent.record_contribution_if_relevant(
                "ai", 78, text, worker, signed_claim("ai", 78, text, worker_key),
            )
        self.assertIsNotNone(payload)
        self.assertEqual(len(self.posted), 1)
        self.assertEqual(self.mirrors, [])


class DidIndexTests(TempStateTestCase):
    """Full DID reveal: the JSON lane carries full did:keys; XAUD keeps an
    abbreviation index so z6Mk…xxxx references resolve in every lane."""

    def test_abbreviate_matches_the_server_text_form(self):
        key, _ = load_key("reveal-agent")
        did = did_of(key)
        abbr = agent.abbreviate_did(did)
        self.assertTrue(abbr.startswith("z6Mk…"))
        self.assertTrue(abbr.endswith(did[-4:]))
        self.assertEqual(len(abbr), len("z6Mk…") + 4)
        # Idempotent over the full DID and a passthrough for non-DIDs.
        self.assertEqual(abbr, agent.abbreviate_did(did))
        self.assertEqual(agent.abbreviate_did("just-a-nick"), "just-a-nick")

    def test_every_verified_signer_is_indexed_by_its_abbreviation(self):
        key_a, _ = load_key("reveal-a")
        key_b, _ = load_key("reveal-b")
        st = state.load_state()
        agent.remember_evidence(st, "lobby", 1, signed_claim("lobby", 1, "hi from a", key_a))
        agent.remember_evidence(st, "lobby", 2, signed_claim("lobby", 2, "hi from b", key_b))

        idx = st["did_index"]
        self.assertEqual(idx[agent.abbreviate_did(did_of(key_a))], did_of(key_a))
        self.assertEqual(idx[agent.abbreviate_did(did_of(key_b))], did_of(key_b))

    def test_resolve_sender_reveals_full_dids_from_abbreviations(self):
        key, _ = load_key("reveal-agent")
        did = did_of(key)
        st = state.load_state()
        agent.remember_evidence(st, "lobby", 1, signed_claim("lobby", 1, "signed", key))

        # Full DID passes through even without the index.
        self.assertEqual(agent.resolve_sender(st, did), did)
        # Known abbreviation resolves to the full DID.
        abbr = agent.abbreviate_did(did)
        self.assertEqual(agent.resolve_sender(st, abbr), did)
        # Unknown abbreviation and unsigned nicknames stay unresolved.
        self.assertIsNone(agent.resolve_sender(st, "z6Mk…nope"))
        self.assertIsNone(agent.resolve_sender(st, "~some-nick"))
        self.assertIsNone(agent.resolve_sender(st, None))

    def test_state_defaults_include_the_did_index(self):
        fresh = state.new_state()
        self.assertEqual(fresh["did_index"], {})
        self.assertEqual(fresh["evidence_log"], {})


class ObserveXaudRecordTests(unittest.TestCase):
    def test_registry_records_from_other_posters_are_acknowledged(self):
        text = xr.build_settlement_frame(
            contract=CONTRACT,
            payer="did:key:z6Mk" + "7" * 44,
            payee="did:key:z6Mk" + "8" * 44,
            amount="1",
            asset="FLOP",
            evidence_room=DEAL_ROOM,
            evidence_seq=4,
        )
        self.assertTrue(agent.observe_xaud_record(DEAL_ROOM, 4, text))

    def test_attestation_frames_pass_through_to_the_attestation_handler(self):
        agent_key, _ = load_key("observe-agent")
        evaluator_key, _ = load_key("observe-evaluator")
        text = build_attestation_frame(
            agent_did=did_of(agent_key),
            evaluator_did=did_of(evaluator_key),
            contract=CONTRACT,
            job_id="task-3f",
            task_type="audit",
            verdict="passed",
            criteria="reproducible",
            evidence=["room:audits seq:1"],
            summary="Audit passed.",
            nonce="1",
        )
        self.assertFalse(agent.observe_xaud_record("xaud", 1, text))

    def test_plain_text_and_invalid_records_are_not_consumed(self):
        self.assertFalse(agent.observe_xaud_record("lobby", 1, "ordinary chatter"))
        self.assertFalse(agent.observe_xaud_record("lobby", 1, "xaud1 {broken"))


class TclkTerminalOutcomeTests(TempStateTestCase):
    """Phase A: fold every verifiable terminal outcome, not just claimed
    receipts, and keep the normalized facts in the work ledger."""

    def drive(self, terminal):
        frames, records, *_ = full_claimed_transcript(terminal=terminal)
        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)
        return state.load_state()

    def assert_posted_outcome(self, expected_outcome):
        room, text = self.latest_post()
        self.assertEqual(room, "xaud")
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["type"], "settlement")
        self.assertEqual(frame["outcome"], expected_outcome)
        self.assertEqual(frame["status"], "terms_verified")
        return frame

    def test_claim_is_posted_at_the_reveal_without_waiting_for_a_receipt(self):
        frames, records, payer, payee, *_ = full_claimed_transcript(terminal="reveal-only")
        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)
        frame = self.assert_posted_outcome("claimed")
        # Evidence points at the reveal (deal room, seq 4), not a receipt.
        self.assertEqual(frame["evidence"], {
            "room": DEAL_ROOM,
            "seq": 4,
            "offer_room": "tclk-offers",
            "offer_seq": 1,
        })
        self.assertEqual(frame["payer"], payer)
        self.assertEqual(frame["payee"], payee)

    def test_refunded_deal_posts_a_refunded_settlement(self):
        frames, records, payer, payee, *_ = full_claimed_transcript(terminal="refunded")
        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)
        frame = self.assert_posted_outcome("refunded")
        self.assertEqual(frame["payer"], payer)
        self.assertEqual(frame["payee"], payee)
        self.assertIn("refunded", frame["summary"])
        self.assertEqual(frame["evidence"]["room"], DEAL_ROOM)
        self.assertEqual(frame["evidence"]["seq"], 4)  # the refund frame

    def test_cancelled_after_accept_posts_a_cancelled_settlement(self):
        frames, records, payer, payee, *_ = full_claimed_transcript(terminal="cancelled")
        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)
        frame = self.assert_posted_outcome("cancelled")
        self.assertEqual(frame["payer"], payer)
        self.assertEqual(frame["payee"], payee)
        self.assertIn("cancelled before payment", frame["summary"])
        self.assertEqual(frame["evidence"]["room"], "tclk-offers")  # cancels live there

    def test_offer_cancelled_before_accept_publishes_nothing(self):
        frames, records, *_ = full_claimed_transcript(terminal="proposed-cancel")
        for (room, seq, frame, _key), record in zip(frames, records):
            agent.observe_tclk_frame(room, seq, frame_text_for(record), record)
        self.assertEqual(self.posted, [])

    def test_ledger_holds_one_normalized_verified_entry_per_contract(self):
        self.drive("claimed")
        self.drive("reveal-only")  # same contract; must not double post or rewrite
        self.assertEqual(len(self.posted), 1)

        ledger = state.load_state()["xaud_ledger"]
        self.assertEqual(len(ledger), 1)
        entry = ledger[CONTRACT]
        self.assertEqual(entry["contract"], CONTRACT)
        self.assertTrue(entry["verified"])
        self.assertEqual(entry["outcome"], "claimed")
        self.assertEqual(entry["amount"], "1000000")
        self.assertEqual(entry["asset"], "FLOP")
        self.assertEqual(entry["job"], {"proto": "a2a", "id": "task-3f"})
        self.assertEqual(entry["offer_room"], "tclk-offers")
        self.assertEqual(entry["offer_seq"], 1)
        self.assertEqual(entry["deal_room"], DEAL_ROOM)
        self.assertEqual(entry["terminal_type"], "reveal")
        self.assertEqual(entry["terminal_room"], DEAL_ROOM)
        self.assertEqual(entry["terminal_seq"], 4)

    def test_state_defaults_include_the_ledger(self):
        fresh = state.new_state()
        self.assertIn("xaud_ledger", fresh)
        self.assertEqual(fresh["xaud_ledger"], {})


class SettlementFromFoldTests(TempStateTestCase):
    def test_helper_handles_refunded_and_cancelled_folds(self):
        from tclk_observer import fold_tclk_transcript

        for terminal, expected_outcome in (("refunded", "refunded"), ("cancelled", "cancelled")):
            frames, records, payer, payee, secret, statement = full_claimed_transcript(terminal=terminal)
            folded = fold_tclk_transcript([dict(r) for r in records])
            self.assertTrue(folded["verified"], terminal)
            text = agent.build_settlement_frame_from_fold(CONTRACT, folded)
            frame = xr.parse_xaud_record(text)
            self.assertEqual(frame["outcome"], expected_outcome)
            self.assertEqual(frame["payer"], payer)
            self.assertEqual(frame["payee"], payee)

    def test_helper_builds_frame_directly_from_a_folded_transcript(self):
        frames, records, payer, payee, secret, statement = full_claimed_transcript()
        transcript = [dict(r) for r in records]
        from tclk_observer import fold_tclk_transcript

        folded = fold_tclk_transcript(transcript)
        self.assertTrue(folded["verified"])

        text = agent.build_settlement_frame_from_fold(CONTRACT, folded)
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["payer"], payer)
        self.assertEqual(frame["payee"], payee)
        self.assertEqual(frame["amount"], "1000000")
        self.assertEqual(frame["asset"], "FLOP")
        self.assertEqual(frame["evidence"]["seq"], 4)


def frame_text_for(record):
    """Reconstruct the raw text a record carries."""
    return record["text"]


class LifecycleFoldTests(unittest.TestCase):
    """fold_tclk_lifecycle verifies a deal whose offer was never observed (P3)."""

    def _records_without_offer(self, terminal):
        _frames, records, *_ = full_claimed_transcript(terminal=terminal)
        return records[1:]

    def test_folds_claimed_from_accept_lock_reveal(self):
        result = fold_tclk_lifecycle(self._records_without_offer("claimed"))
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "claimed")
        self.assertIsNone(result["offer"])
        self.assertNotIn("amount", result)

    def test_folds_refunded_from_accept_lock_refund(self):
        result = fold_tclk_lifecycle(self._records_without_offer("refunded"))
        self.assertTrue(result["verified"])
        self.assertEqual(result["status"], "refunded")

    def test_rejects_a_transcript_that_still_carries_an_offer(self):
        _frames, records, *_ = full_claimed_transcript()
        self.assertFalse(fold_tclk_lifecycle(records)["verified"])

    def test_rejects_a_lone_terminal_frame(self):
        _frames, records, *_ = full_claimed_transcript()
        self.assertFalse(fold_tclk_lifecycle(records[2:])["verified"])


class FetchRoomLimitTests(unittest.TestCase):
    """The firehose rooms must be drained with the largest page the venue
    returns; a default 50-message page silently drops the rest of a fast
    ring (P1)."""

    def test_limit_and_since_are_sent_in_the_query(self):
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"room":"tclk-offers","count":0,"messages":[]}'

        def fake_urlopen(request, timeout=None):
            captured["url"] = request.full_url
            return FakeResponse()

        with mock.patch.object(
            agent.urllib.request, "urlopen", side_effect=fake_urlopen
        ):
            messages, code = agent.fetch_room(
                "tclk-offers", 2521341, wait=False, limit=200
            )

        self.assertEqual(messages, [])
        self.assertIsNone(code)
        self.assertIn("since=2521341", captured["url"])
        self.assertIn("limit=200", captured["url"])
        self.assertIn("wait=0", captured["url"])


class QuerySurfaceTests(unittest.TestCase):
    def test_query_options_are_bounded_and_parsed(self):
        terms, options = agent._parse_query_options(
            "audit limit:99 min_score:12 since:24h"
        )
        self.assertEqual(terms, "audit")
        self.assertEqual(options["limit"], 20)
        self.assertEqual(options["min_score"], 12)
        self.assertGreater(options["since"], 0)

    def test_machine_query_has_stable_wire_prefix(self):
        payload = agent._machine_query({"version": "xaudq1", "results": []})
        self.assertTrue(payload.startswith("xaudq1 "))
        self.assertEqual(json.loads(payload[len("xaudq1 "):])["version"], "xaudq1")

    def test_runtime_health_reports_stale_state(self):
        health = agent._runtime_health(
            {"runtime": {"last_tick_at": 100, "last_error": "503"}},
            140,
        )
        self.assertEqual(health["status"], "stale")
        self.assertEqual(health["last_error"], "503")


class DealRoomPruneTests(TempStateTestCase):
    """Deal rooms must not accumulate for contracts that are gone (P4)."""

    def test_prune_drops_rooms_for_evicted_contracts(self):
        keep = "0x" + "a" * 64
        drop = "0x" + "b" * 64
        st = state.load_state()
        st["tclk_contracts"] = {keep: {"updated_at": 1.0, "transcript": []}}
        keep_room, drop_room = agent.deal_room(keep), agent.deal_room(drop)
        st["tclk_rooms"] = [keep_room, drop_room]
        st["room_cursors"] = {keep_room: 1, drop_room: 2, "lobby": 3}

        agent.prune_deal_rooms(st)

        self.assertEqual(st["tclk_rooms"], [keep_room])
        self.assertIn(keep_room, st["room_cursors"])
        self.assertNotIn(drop_room, st["room_cursors"])
        self.assertEqual(st["room_cursors"]["lobby"], 3)


if __name__ == "__main__":
    unittest.main()
