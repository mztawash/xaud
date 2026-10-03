import hashlib
import json
import unittest

import agent
from contribution_registry import (
    ContributionRegistry,
    build_kibble_scoreboard_message,
    build_registry_message,
    detect_task,
    score_contribution,
    sanitize_room_name,
)
from tclk_observer import (
    TclkFrameError,
    deal_room,
    event_assertion,
    fold_tclk_transcript,
    is_reputation_evidence,
    order_tclk_records,
    parse_tclk_frame,
    verify_transport_record,
)
from xaud_attestation import (
    AttestationError,
    build_attestation_frame,
    parse_attestation,
    verify_attestation_record,
)
from sign import did_of, load_key, signature


class ContributionRegistryTests(unittest.TestCase):
    def test_detect_task_handles_builder_messages(self):
        self.assertEqual(detect_task("I built a verifier for DID setup and signed activity."), "builder")

    def test_agent_normalize_text_returns_normalized_text(self):
        self.assertEqual(agent.normalize_text("  Network\nhealth  "), "network health")

    def test_active_rooms_include_registry_and_tclk_rendezvous(self):
        self.assertIn("tclk-offers", agent.ACTIVE_ROOMS)
        self.assertIn("xaud", agent.ACTIVE_ROOMS)
        self.assertIn("close1", agent.ACTIVE_ROOMS)
        self.assertIn("d-close1-flow", agent.ACTIVE_ROOMS)

    def test_saved_tclk_cursor_rooms_are_eligible_for_restart_restore(self):
        state = {
            "room_cursors": {"mb-p-tclk-" + "a" * 16: 7},
            "tclk_rooms": [],
            "tclk_contracts": {},
        }
        persisted = set(state["tclk_rooms"])
        persisted.update(
            room for room in state["room_cursors"]
            if room.startswith("mb-p-tclk-")
        )
        self.assertIn("mb-p-tclk-" + "a" * 16, persisted)

    def test_score_contribution_rewards_verifiable_work(self):
        score, tags = score_contribution(
            "I built a validator that checks profile notes and signed DID activity for agents.",
            sender_did="did:key:test",
        )
        self.assertGreater(score, 8)
        self.assertIn("builder", tags)
        # "signed"/"DID" are not work evidence on their own: no generic
        # verified tag, even though the message contains verification words.
        self.assertNotIn("verified", tags)

    def test_score_contribution_no_bonus_for_bare_verification_claims(self):
        # The exact spam pattern that polluted the registry: a self-declared
        # "verification executed + proof hash" line with no deliverable.
        score, tags = score_contribution(
            "State verification executed on Block #965884. Calculation proof: 9db89ff0.",
        )
        self.assertLess(score, 3)
        self.assertNotIn("verified", tags)

    def test_score_contribution_penalizes_presence_ping(self):
        score, tags = score_contribution("Another day, another check-in. The agentic economy narrative is really picking up.")
        self.assertLess(score, 4)
        self.assertIn("low-value", tags)

    def test_registry_publish_creates_a_room_record(self):
        registry = ContributionRegistry(room_name="xaud")
        record = registry.publish(
            agent_did="did:key:z6Mkexample",
            message="I verified a DID profile note and published the result in a room.",
            evidence="room:xaud seq:4215",
            status="verified",
        )
        self.assertEqual(record["room"], "xaud")
        self.assertEqual(record["status"], "verified")
        self.assertGreater(record["score"], 0)
        self.assertIn("agent_did", record)
        self.assertIn("task", record)

    def test_registry_keeps_unresolved_sender_status_explicit(self):
        registry = ContributionRegistry(room_name="xaud")
        record = registry.publish(
            agent_did="z6Mk...51PD",
            message="Audited the validator configuration and published the report at https://example.test/audit.",
            evidence="room:validators seq:99",
            status="observed",
            identity_status="unresolved_sender",
        )
        self.assertEqual(record["identity_status"], "unresolved_sender")
        self.assertIn("identity_status=unresolved_sender", record["message"])

    def test_detect_task_covers_audits_collaboration_and_research(self):
        self.assertEqual(detect_task("Audited the validator and published the report."), "audit")
        self.assertEqual(detect_task("We collaborated on a joint implementation and shipped the result."), "collaboration")
        self.assertEqual(detect_task("Wrote and published research with a reproducible result."), "research")

    def test_registry_defaults_to_xaud(self):
        self.assertEqual(ContributionRegistry().room_name, "xaud")

    def test_sanitize_room_name_normalizes_registry_room(self):
        self.assertEqual(sanitize_room_name(" XAUD!! "), "xaud")

    def test_build_registry_message_includes_task_and_score(self):
        message = build_registry_message(
            agent_did="did:key:test",
            room="xaud",
            task="builder",
            score=9,
            tags=["builder", "verified"],
            evidence="room:lobby seq:42",
            summary="I built a verifier for signed DID checks.",
        )
        self.assertIn("task=builder", message)
        self.assertIn("score=9", message)
        self.assertIn("room=xaud", message)

    def test_build_kibble_scoreboard_message_uses_kibble_flow(self):
        message = build_kibble_scoreboard_message(
            agent_did="did:key:test",
            room="kibble",
            task="builder",
            score=9,
            tags=["builder", "verified"],
            evidence="room:lobby seq:42",
            summary="I built a verifier for signed DID checks.",
        )
        self.assertIn("JOB", message)
        self.assertIn("phase=ATTEST", message)
        self.assertIn("score=9", message)

    def test_is_own_sender_handles_full_and_abbreviated_did_forms(self):
        self.assertTrue(agent.is_own_sender(agent.EXPECTED_DID))
        self.assertTrue(agent.is_own_sender("z6Mk…4mBQ"))
        self.assertFalse(agent.is_own_sender("did:key:z6Mkother"))

    def test_explicit_contribution_requires_action_and_evidence(self):
        self.assertTrue(agent.is_explicit_contribution(
            "Published a guide with the test result at https://example.test/guide."
        ))

    def test_explicit_contribution_rejects_presence_status(self):
        self.assertFalse(agent.is_explicit_contribution(
            "Agent node reporting in. Ed25519 identity verified."
        ))

    def test_explicit_contribution_accepts_completed_trade_evidence(self):
        self.assertTrue(agent.is_explicit_contribution(
            "Executed the trade and published the receipt hash."
        ))

    def test_extract_agent_did_uses_full_did_in_message(self):
        observed_did = "did:key:z6Mkg59iL4k3hPUAGFKzEM9EQRxFLtn5W18q2XcuiVPz4mBQ"
        self.assertEqual(
            agent.extract_agent_did(
                "z6Mk...4mBQ",
                f"Published a guide. DID: {observed_did}",
            ),
            observed_did,
        )

    def test_extract_agent_did_rejects_abbreviated_only_sender(self):
        self.assertIsNone(agent.extract_agent_did("z6Mk...4mBQ", "Published a guide."))

    def test_extract_agent_identity_retains_abbreviated_sender_reference(self):
        self.assertEqual(
            agent.extract_agent_identity("z6Mk...4mBQ", "Published a guide."),
            ("z6Mk...4mBQ", "unresolved_sender"),
        )

    def test_tclk_parser_extracts_signed_identity_and_contract(self):
        frame = parse_tclk_frame(
            'tclk1 {"contract":"0x' + "a" * 64 +
            '","from":"did:key:z6Mkg59iL4k3hPUAGFKzEM9EQRxFLtn5W18q2XcuiVPz4mBQ",'
            '"type":"reveal"}'
        )
        self.assertEqual(frame["type"], "reveal")
        self.assertEqual(event_assertion(frame), "payment_claim_announced")
        self.assertTrue(is_reputation_evidence(frame))

    def test_tclk_offer_does_not_count_as_completed_work(self):
        frame = parse_tclk_frame(
            'tclk1 {"from":"did:key:z6Mkg59iL4k3hPUAGFKzEM9EQRxFLtn5W18q2XcuiVPz4mBQ",'
            '"id":"0x' + "e" * 64 + '",'
            '"type":"offer"}'
        )
        self.assertFalse(is_reputation_evidence(frame))

    def test_tclk_heartbeat_is_liveness_only(self):
        frame = parse_tclk_frame(
            'tclk1 {"contract":"0x' + "b" * 64 +
            '","from":"did:key:z6Mkg59iL4k3hPUAGFKzEM9EQRxFLtn5W18q2XcuiVPz4mBQ",'
            '"type":"heartbeat"}'
        )
        self.assertEqual(event_assertion(frame), "liveness_only")
        self.assertFalse(is_reputation_evidence(frame))

    def test_tclk_deal_room_is_derived_from_contract(self):
        self.assertEqual(deal_room("0x" + "c" * 64), "mb-p-tclk-cccccccccccccccc")

    def test_tclk_parser_rejects_missing_full_identity(self):
        with self.assertRaises(TclkFrameError):
            parse_tclk_frame(
                'tclk1 {"contract":"0x' + "d" * 64 +
                '","from":"z6Mk...4mBQ","type":"reveal"}'
            )

    def test_json_room_records_preserve_transport_fields(self):
        payload = json.dumps({
            "messages": [{
                "seq": 7,
                "ts": "2026-09-04T00:00:00Z",
                "from": "did:key:test",
                "text": "hello",
                "nonce": 11,
                "sig": "signature",
            }]
        })
        record = agent.parse_messages(payload)[0]
        self.assertEqual(record["sender"], "did:key:test")
        self.assertEqual(record["nonce"], 11)
        self.assertEqual(record["sig"], "signature")

    def test_transport_signature_verifies_against_did(self):
        key, _ = load_key("tclk-test-seed")
        sender = did_of(key)
        text = 'tclk1 {"from":"' + sender + '","id":"0x' + "e" * 64 + '","type":"offer"}'
        nonce = 123
        record = {
            "from": sender,
            "nonce": nonce,
            "text": text,
            "sig": signature(key, f"audit-room|{nonce}|{text}"),
        }
        self.assertTrue(verify_transport_record("audit-room", record))
        record["text"] += " altered"
        self.assertFalse(verify_transport_record("audit-room", record))

    def test_tclk_fold_verifies_claimed_hash_lock_deal(self):
        payer_key, _ = load_key("tclk-payer")
        payee_key, _ = load_key("tclk-payee")
        payer = did_of(payer_key)
        payee = did_of(payee_key)
        offer_id = "0x" + "1" * 64
        contract = "0x" + "2" * 64
        secret = bytes(range(32))
        statement = "0x" + hashlib.sha256(secret).hexdigest()

        def record(room, seq, frame, key, ts="2026-09-04T20:00:00Z"):
            text = "tclk1 " + json.dumps(frame, sort_keys=True, separators=(",", ":"))
            nonce = str(seq)
            return {
                "room": room,
                "seq": seq,
                "ts": ts,
                "from": frame["from"],
                "nonce": nonce,
                "text": text,
                "sig": signature(key, f"{room}|{nonce}|{text}"),
            }

        offer = record("tclk-offers", 1, {
            "amount": "1",
            "asset": "PAPER",
            "claimByMs": 1790000000000,
            "expiresMs": 1789990000000,
            "from": payer,
            "id": offer_id,
            "job": {"proto": "a2a", "id": "task-1"},
            "lock": "hash",
            "nonce": "offer",
            "rails": ["paper"],
            "refundAfterMs": 1790001000000,
            "role": "payer",
            "type": "offer",
        }, payer_key)
        accept = record("tclk-offers", 2, {
            "contract": contract,
            "from": payee,
            "nonce": "accept",
            "ref": offer_id,
            "statement": statement,
            "type": "accept",
        }, payee_key)
        room = deal_room(contract)
        lock = record(room, 3, {
            "contract": contract,
            "from": payer,
            "rail": "paper",
            "ref": "paper-1",
            "type": "lock",
        }, payer_key)
        reveal = record(room, 4, {
            "contract": contract,
            "from": payee,
            "ref": "paper-1",
            "secret": "0x" + secret.hex(),
            "type": "reveal",
        }, payee_key)
        receipt = record(room, 5, {
            "contract": contract,
            "from": payer,
            "outcome": "claimed",
            "type": "receipt",
        }, payer_key)

        folded = fold_tclk_transcript([offer, accept, lock, reveal, receipt])
        self.assertTrue(folded["verified"])
        self.assertEqual(folded["status"], "claimed")
        self.assertEqual(folded["job"]["id"], "task-1")

        reveal["text"] = reveal["text"].replace(secret.hex(), (b"x" * 32).hex())
        tampered = fold_tclk_transcript([offer, accept, lock, reveal, receipt])
        self.assertFalse(tampered["verified"])

    def test_work_attestation_requires_independent_evaluator(self):
        key, _ = load_key("attestation-agent")
        did = did_of(key)
        with self.assertRaises(AttestationError):
            build_attestation_frame(
                agent_did=did,
                evaluator_did=did,
                contract="0x" + "a" * 64,
                job_id="task-1",
                task_type="audit",
                verdict="passed",
                criteria="report is reproducible",
                evidence=["room:audits seq:1"],
                summary="Audit passed.",
                nonce="1",
            )

    def test_signed_work_attestation_maps_passed_to_work_verified(self):
        agent_key, _ = load_key("attestation-agent")
        evaluator_key, _ = load_key("attestation-evaluator")
        agent_did = did_of(agent_key)
        evaluator_did = did_of(evaluator_key)
        text = build_attestation_frame(
            agent_did=agent_did,
            evaluator_did=evaluator_did,
            contract="0x" + "b" * 64,
            job_id="audit-1",
            task_type="audit",
            verdict="passed",
            criteria="all findings reproduce",
            evidence=["room:agent-security seq:42", "note:audit-report"],
            summary="Validator audit passed.",
            nonce="2",
        )
        record = {
            "from": evaluator_did,
            "nonce": "99",
            "text": text,
            "sig": signature(evaluator_key, f"xaud|99|{text}"),
        }
        verdict = verify_attestation_record("xaud", record)
        self.assertTrue(verdict["verified"])
        self.assertEqual(verdict["status"], "work_verified")
        self.assertEqual(parse_attestation(text)["job_id"], "audit-1")


class TranscriptOrderTests(unittest.TestCase):
    """Transcript records are re-ordered into tclk/1 protocol order (P2)."""

    DID_A = "did:key:z6Mk" + "A" * 44
    DID_B = "did:key:z6Mk" + "B" * 44
    OFFER_ID = "0x" + "1" * 64
    CONTRACT = "0x" + "2" * 64

    def _rec(self, room, seq, frame):
        return {
            "room": room,
            "seq": seq,
            "text": "tclk1 " + json.dumps(
                frame, sort_keys=True, separators=(",", ":")
            ),
        }

    def test_scrambled_records_come_back_in_protocol_order(self):
        deal = deal_room(self.CONTRACT)
        reveal = self._rec(deal, 4, {
            "contract": self.CONTRACT, "from": self.DID_B,
            "secret": "0x" + "a" * 64, "type": "reveal",
        })
        lock = self._rec(deal, 3, {
            "contract": self.CONTRACT, "from": self.DID_A,
            "rail": "paper", "ref": "r", "type": "lock",
        })
        offer = self._rec("tclk-offers", 1, {
            "id": self.OFFER_ID, "from": self.DID_A, "role": "payer",
            "amount": "1", "asset": "X", "type": "offer",
        })
        accept = self._rec("tclk-offers", 2, {
            "contract": self.CONTRACT, "ref": self.OFFER_ID,
            "from": self.DID_B, "statement": "0x" + "b" * 64,
            "type": "accept",
        })

        ordered = order_tclk_records([reveal, lock, accept, offer])
        self.assertEqual(
            [r["seq"] for r in ordered], [1, 2, 3, 4]
        )

    def test_duplicate_records_are_dropped(self):
        deal = deal_room(self.CONTRACT)
        lock = self._rec(deal, 3, {
            "contract": self.CONTRACT, "from": self.DID_A,
            "rail": "paper", "ref": "r", "type": "lock",
        })
        ordered = order_tclk_records([lock, dict(lock)])
        self.assertEqual(len(ordered), 1)


if __name__ == "__main__":
    unittest.main()
