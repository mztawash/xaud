"""Tests for canonical xaud1 registry-record frames (xaud_records.py).

Pins three contracts so they cannot drift apart:
  1. the canonical wire format (xaud1 prefix, sorted keys, ASCII-only single line),
  2. fail-closed decode behaviour (nothing is coerced, everything is rejected loudly),
  3. module <-> JSON schema field and enum agreement (schema/xaud1-records.schema.json).

Run from the repository root:
    .venv/bin/python -m unittest discover -s tests
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import xaud_records as xr
from contribution_registry import ACTIVITY_TYPES

DID_A = "did:key:z6Mk" + "1" * 44
DID_B = "did:key:z6Mk" + "2" * 44
DID_C = "did:key:z6Mk" + "3" * 44
CONTRACT = "0x" + "a" * 64

SCHEMA = json.loads((ROOT / "schema" / "xaud1-records.schema.json").read_text())


def canonical(obj):
    return "xaud1 " + json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class CanonicalEncodingTests(unittest.TestCase):
    def test_prefix_is_xaud1_space(self):
        self.assertEqual(xr.XAUD_PREFIX, "xaud1 ")

    def test_encoded_text_is_ascii_single_line_and_canonical(self):
        frame = {
            "asset": "FLOP",
            "evidence": {"room": "tclk-offers", "seq": 7},
            "summary": "Compra de π tokens — done ✓",
            "type": "observation",
            "version": "xaud1",
            "status": "observed",
            "identity_status": "identified",
            "agent_did": DID_A,
        }
        text = xr.encode_frame(frame)
        # ASCII-only and single-line: the server sweeps Cc/Cf to spaces on write,
        # so raw non-ASCII or control characters would change the stored bytes.
        self.assertTrue(all(ord(ch) < 128 for ch in text))
        self.assertNotIn("\n", text)
        self.assertNotIn("\r", text)
        self.assertEqual(text, canonical(frame))

    def test_encoded_text_decodes_to_the_same_frame(self):
        frame = {
            "type": "settlement",
            "version": "xaud1",
            "contract": CONTRACT,
            "payer": DID_A,
            "payee": DID_B,
            "amount": "250",
            "asset": "FLOP",
            "outcome": "claimed",
            "status": "terms_verified",
            "verified_by": "transcript",
            "rail": "flop-htlc",
            "evidence": {"room": "mb-p-tclk-aaaaaaaaaaaaaaaa", "seq": 4},
        }
        self.assertEqual(json.loads(xr.encode_frame(frame)[len("xaud1 "):]), frame)

    def test_encode_requires_a_json_object(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.encode_frame(["not", "an", "object"])

    def test_max_frame_chars_is_message_cap(self):
        self.assertEqual(xr.MAX_FRAME_CHARS, 4096)

    def test_oversized_frame_is_rejected(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.build_observation_frame(
                evidence_room="lobby",
                evidence_seq=1,
                summary="x" * 5000,
                agent_did=DID_A,
            )


class SettlementFrameTests(unittest.TestCase):
    def setUp(self):
        self.base = dict(
            contract=CONTRACT,
            payer=DID_A,
            payee=DID_B,
            amount="1000000",
            asset="FLOP",
            evidence_room="mb-p-tclk-aaaaaaaaaaaaaaaa",
            evidence_seq=5,
        )

    def build(self, **overrides):
        return xr.build_settlement_frame(**{**self.base, **overrides})


    def test_builds_a_minimal_valid_frame(self):
        text = xr.build_settlement_frame(**self.base)
        self.assertTrue(text.startswith("xaud1 "))
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["type"], "settlement")
        self.assertEqual(frame["version"], "xaud1")
        self.assertEqual(frame["outcome"], "claimed")
        self.assertEqual(frame["status"], "terms_verified")
        self.assertEqual(frame["verified_by"], "transcript")
        self.assertEqual(frame["payer"], DID_A)
        self.assertEqual(frame["payee"], DID_B)
        self.assertEqual(frame["evidence"], {"room": "mb-p-tclk-aaaaaaaaaaaaaaaa", "seq": 5})

    def test_builds_a_full_frame_with_optional_fields(self):
        text = self.build(
            rail="flop-htlc",
            job={"proto": "a2a", "id": "task-3f", "context": "ctx-1"},
            summary="swap executed",
            offer_room="tclk-offers",
            offer_seq=2,
        )
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["rail"], "flop-htlc")
        self.assertEqual(frame["job"], {"proto": "a2a", "id": "task-3f", "context": "ctx-1"})
        self.assertEqual(frame["summary"], "swap executed")
        self.assertEqual(
            frame["evidence"],
            {"room": "mb-p-tclk-aaaaaaaaaaaaaaaa", "seq": 5, "offer_room": "tclk-offers", "offer_seq": 2},
        )

    def test_amount_and_asset_must_be_well_formed(self):
        for amount in ("", "1.5", "12a", "-3"):
            with self.assertRaises(xr.XaudRecordError):
                self.build(amount=amount)
        with self.assertRaises(xr.XaudRecordError):
            self.build(asset="")

    def test_payer_and_payee_must_differ(self):
        with self.assertRaises(xr.XaudRecordError):
            self.build(payee=DID_A)

    def test_payer_and_payee_must_be_full_dids(self):
        with self.assertRaises(xr.XaudRecordError):
            self.build(payer="z6Mk...abbr")

    def test_contract_must_be_tclk_contract_id(self):
        with self.assertRaises(xr.XaudRecordError):
            self.build(contract="0xabc")

    def test_outcome_status_verified_by_are_pinned(self):
        with self.assertRaises(xr.XaudRecordError):
            self.build(outcome="unpaid")
        # outcome=refunded is legal for a settlement; status and verified_by are
        # constants, so a raw frame can carry any outcome but not other values.
        frame = xr.parse_xaud_record(self.build(outcome="refunded"))
        self.assertEqual(frame["status"], "terms_verified")
        wrong_status = {
            "type": "settlement",
            "version": "xaud1",
            "contract": CONTRACT,
            "payer": DID_A,
            "payee": DID_B,
            "amount": "1",
            "asset": "FLOP",
            "outcome": "claimed",
            "status": "observed",
            "verified_by": "transcript",
            "evidence": {"room": "r", "seq": 1},
        }
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record(canonical(wrong_status))
        wrong_verified_by = dict(wrong_status, status="terms_verified", verified_by="attestation")
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record(canonical(wrong_verified_by))

    def test_rail_pattern(self):
        with self.assertRaises(xr.XaudRecordError):
            self.build(rail="Not A Rail!")

    def test_job_requires_id_and_known_keys_only(self):
        with self.assertRaises(xr.XaudRecordError):
            self.build(job={"proto": "a2a"})
        with self.assertRaises(xr.XaudRecordError):
            self.build(job={"id": "x", "bogus": 1})

    def test_unknown_fields_are_rejected(self):
        frame = {
            "type": "settlement",
            "version": "xaud1",
            "contract": CONTRACT,
            "payer": DID_A,
            "payee": DID_B,
            "amount": "1",
            "asset": "FLOP",
            "outcome": "claimed",
            "status": "terms_verified",
            "verified_by": "transcript",
            "evidence": {"room": "r", "seq": 1},
            "extra_field": True,
        }
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record(canonical(frame))


    def test_terms_tier_requires_amount_and_asset(self):
        # Default status is the terms-known tier, so amount/asset are required.
        with self.assertRaises(xr.XaudRecordError):
            xr.build_settlement_frame(
                contract=CONTRACT,
                payer=DID_A,
                payee=DID_B,
                evidence_room="mb-p-tclk-aaaaaaaaaaaaaaaa",
                evidence_seq=4,
            )

    def test_outcome_tier_omits_terms(self):
        text = xr.build_settlement_frame(
            contract=CONTRACT,
            payer=DID_A,
            payee=DID_B,
            outcome="claimed",
            status="outcome_verified",
            evidence_room="mb-p-tclk-aaaaaaaaaaaaaaaa",
            evidence_seq=4,
        )
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["status"], "outcome_verified")
        self.assertNotIn("amount", frame)
        self.assertNotIn("asset", frame)

    def test_outcome_tier_rejects_smuggled_terms(self):
        for field in ({"amount": "1"}, {"asset": "FLOP"}):
            with self.assertRaises(xr.XaudRecordError):
                xr.build_settlement_frame(
                    contract=CONTRACT,
                    payer=DID_A,
                    payee=DID_B,
                    status="outcome_verified",
                    evidence_room="mb-p-tclk-aaaaaaaaaaaaaaaa",
                    evidence_seq=4,
                    **field,
                )

    def test_legacy_transcript_verified_reads_as_terms(self):
        # Records posted before the terms/outcome split must keep decoding, and
        # must still carry the amount and asset they were published with.
        frame = {
            "type": "settlement",
            "version": "xaud1",
            "contract": CONTRACT,
            "payer": DID_A,
            "payee": DID_B,
            "amount": "1",
            "asset": "FLOP",
            "outcome": "claimed",
            "status": "transcript_verified",
            "verified_by": "transcript",
            "evidence": {"room": "r", "seq": 1},
        }
        parsed = xr.parse_xaud_record(canonical(frame))
        self.assertEqual(parsed["status"], "transcript_verified")
        self.assertEqual(
            xr.canonical_settlement_status(parsed["status"]), "terms_verified"
        )

    def test_legacy_status_still_requires_terms(self):
        frame = {
            "type": "settlement",
            "version": "xaud1",
            "contract": CONTRACT,
            "payer": DID_A,
            "payee": DID_B,
            "outcome": "claimed",
            "status": "transcript_verified",
            "verified_by": "transcript",
            "evidence": {"room": "r", "seq": 1},
        }
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record(canonical(frame))


class ObservationFrameTests(unittest.TestCase):
    def test_identified_observation(self):
        text = xr.build_observation_frame(
            evidence_room="ai",
            evidence_seq=9,
            summary="I built a verifier and published the test result.",
            agent_did=DID_C,
            task="builder",
            activity_type="service_job",
            score=10,
            tags=["builder", "verified"],
        )
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["identity_status"], "identified")
        self.assertEqual(frame["agent_did"], DID_C)
        self.assertNotIn("sender", frame)
        self.assertEqual(frame["score"], 10)
        self.assertEqual(frame["tags"], ["builder", "verified"])
        self.assertEqual(frame["status"], "observed")
        self.assertEqual(frame["verified_by"], "none")

    def test_identified_observation_requires_a_full_did(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.build_observation_frame(
                evidence_room="ai",
                evidence_seq=1,
                summary="Built something.",
                agent_did="z6Mk...abbr",
            )

    def test_unresolved_sender_observation(self):
        text = xr.build_observation_frame(
            evidence_room="lobby",
            evidence_seq=3,
            summary="Audited the validator configuration and published the report.",
            identity_status="unresolved_sender",
            sender="z6Mk…51PD",
            task="audit",
            activity_type="audit",
        )
        frame = xr.parse_xaud_record(text)
        self.assertEqual(frame["identity_status"], "unresolved_sender")
        self.assertEqual(frame["sender"], "z6Mk…51PD")
        self.assertNotIn("agent_did", frame)

    def test_exactly_one_identity_field(self):
        # A raw frame carrying both agent_did and sender is malformed.
        both = {
            "type": "observation",
            "version": "xaud1",
            "status": "observed",
            "identity_status": "identified",
            "verified_by": "none",
            "agent_did": DID_C,
            "sender": "z6Mk…x",
            "evidence": {"room": "r", "seq": 1},
            "summary": "Claimed work.",
        }
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record(canonical(both))
        # An identified frame needs a real full DID, and an unresolved frame
        # needs a sender reference.
        with self.assertRaises(xr.XaudRecordError):
            xr.build_observation_frame(
                evidence_room="r",
                evidence_seq=1,
                summary="Claimed work.",
                identity_status="identified",
            )
        with self.assertRaises(xr.XaudRecordError):
            xr.build_observation_frame(
                evidence_room="r",
                evidence_seq=1,
                summary="Claimed work.",
                identity_status="unresolved_sender",
            )

    def test_activity_type_must_be_registered(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.build_observation_frame(
                evidence_room="r",
                evidence_seq=1,
                summary="Built a tool.",
                agent_did=DID_C,
                activity_type="not-a-real-type",
            )
        # Every registered activity type is acceptable.
        for activity in sorted(ACTIVITY_TYPES):
            text = xr.build_observation_frame(
                evidence_room="r",
                evidence_seq=1,
                summary="Did some work.",
                agent_did=DID_C,
                activity_type=activity,
            )
            self.assertEqual(xr.parse_xaud_record(text)["activity_type"], activity)

    def test_score_bounds(self):
        for bad in (-1, 21):
            with self.assertRaises(xr.XaudRecordError):
                xr.build_observation_frame(
                    evidence_room="r",
                    evidence_seq=1,
                    summary="Work.",
                    agent_did=DID_C,
                    score=bad,
                )

    def test_tags_must_be_nonempty_strings(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.build_observation_frame(
                evidence_room="r",
                evidence_seq=1,
                summary="Work.",
                agent_did=DID_C,
                tags=["ok", ""],
            )

    def test_status_and_identity_status_enums(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.build_observation_frame(
                evidence_room="r",
                evidence_seq=1,
                summary="Work.",
                agent_did=DID_C,
                status="guessed",
            )
        with self.assertRaises(xr.XaudRecordError):
            xr.build_observation_frame(
                evidence_room="r",
                evidence_seq=1,
                summary="Work.",
                agent_did=DID_C,
                identity_status="maybe",
            )


class EvidenceAndJobValidationTests(unittest.TestCase):
    def setUp(self):
        self.base = dict(
            evidence_room="lobby",
            evidence_seq=1,
            summary="Built a tool and published the result.",
            agent_did=DID_C,
        )

    def observe(self, **overrides):
        return xr.build_observation_frame(**{**self.base, **overrides})

    def test_evidence_requires_room_and_seq(self):
        for bad in ("Bad Room!", "", "a" * 49, "-lead-dash"):
            with self.assertRaises(xr.XaudRecordError):
                self.observe(evidence_room=bad)

    def test_evidence_seq_must_be_non_negative_int(self):
        for seq in (-1, "7", 1.5, True):
            with self.assertRaises(xr.XaudRecordError):
                self.observe(evidence_seq=seq)

    def test_offer_room_and_seq_are_validated(self):
        with self.assertRaises(xr.XaudRecordError):
            self.observe(offer_room="Not Valid", offer_seq=1)
        frame = xr.parse_xaud_record(self.observe(offer_room="tclk-offers", offer_seq=9))
        self.assertEqual(frame["evidence"]["offer_room"], "tclk-offers")
        self.assertEqual(frame["evidence"]["offer_seq"], 9)

    def test_observation_unknown_fields_are_rejected(self):
        frame = {
            "type": "observation",
            "version": "xaud1",
            "status": "observed",
            "identity_status": "identified",
            "agent_did": DID_C,
            "evidence": {"room": "lobby", "seq": 1},
            "summary": "Built a thing.",
            "verified_by": "none",
            "bogus": 1,
        }
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record(canonical(frame))


class ParseFailClosedTests(unittest.TestCase):
    def test_plain_text_returns_none(self):
        self.assertIsNone(xr.parse_xaud_record("hello world"))
        self.assertIsNone(xr.parse_xaud_record(""))

    def test_malformed_json_is_rejected(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record("xaud1 {not json")

    def test_non_object_json_is_rejected(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record('xaud1 ["a"]')

    def test_wrong_version_is_rejected(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record('xaud1 {"type":"observation","version":"xaud9"}')

    def test_unknown_type_is_rejected(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record('xaud1 {"type":"alien","version":"xaud1"}')

    def test_attestation_frames_belong_to_xaud_attestation(self):
        # A work_attestation is not a registry record; the registry must refuse
        # it loudly instead of half-parsing it.
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record(
                'xaud1 {"type":"work_attestation","version":"xaud1"}'
            )

    def test_missing_required_field_is_rejected(self):
        with self.assertRaises(xr.XaudRecordError):
            xr.parse_xaud_record(
                'xaud1 {"type":"settlement","version":"xaud1"}'
            )


class LegacyReaderTests(unittest.TestCase):
    def test_legacy_full_did_maps_to_agent_did(self):
        record = xr.parse_legacy_registry_record(
            'agent_did=did:key:z6Mkexample room=xaud task=builder score=9 '
            'status=observed identity_status=identified tags=builder,verified '
            'evidence="room:lobby seq:42" summary="I built a verifier for signed checks."'
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["type"], "observation")
        self.assertEqual(record["version"], "xaud0")
        self.assertEqual(record["identity_status"], "identified")
        self.assertEqual(record["score"], 9)
        self.assertEqual(record["tags"], ["builder", "verified"])
        self.assertIn("built a verifier", record["summary"].lower())

    def test_legacy_abbreviated_identity_stays_a_sender(self):
        record = xr.parse_legacy_registry_record(
            'agent_did=z6Mk...51PD status=observed identity_status=unresolved_sender summary="claimed an audit"'
        )
        self.assertEqual(record["sender"], "z6Mk...51PD")
        self.assertNotIn("agent_did", record)

    def test_legacy_non_record_returns_none(self):
        self.assertIsNone(xr.parse_legacy_registry_record("just chatting"))
        self.assertIsNone(xr.parse_legacy_registry_record("no agent field here"))


class SchemaConformanceTests(unittest.TestCase):
    """Pin xaud_records.py constants to schema/xaud1-records.schema.json."""

    def test_required_fields_match_schema(self):
        for record_type in ("settlement", "observation"):
            module_set = xr.REQUIRED_FIELDS[record_type]
            schema_set = set(SCHEMA["$defs"][record_type]["required"])
            self.assertEqual(module_set, schema_set, record_type)

    def test_allowed_fields_match_schema_properties(self):
        for record_type in ("settlement", "observation"):
            module_set = xr.REQUIRED_FIELDS[record_type] | xr.OPTIONAL_FIELDS[record_type]
            schema_set = set(SCHEMA["$defs"][record_type]["properties"])
            self.assertEqual(module_set, schema_set, record_type)

    def test_shared_constants_match_schema_enums(self):
        def schema_constraint(record_type, field):
            prop = SCHEMA["$defs"][record_type]["properties"][field]
            if "const" in prop:
                return {prop["const"]}
            return set(prop.get("enum", []))

        self.assertEqual(xr.OUTCOMES, schema_constraint("settlement", "outcome"))
        # The schema enum carries the current tiers plus the legacy status kept
        # for records already published in /r/xaud.
        self.assertEqual(
            xr.ALL_SETTLEMENT_STATUSES, schema_constraint("settlement", "status")
        )
        self.assertEqual({"transcript"}, schema_constraint("settlement", "verified_by"))
        self.assertEqual(xr.OBSERVATION_STATUSES, schema_constraint("observation", "status"))
        self.assertEqual(
            xr.OBSERVATION_IDENTITY_STATUSES,
            schema_constraint("observation", "identity_status"),
        )
        self.assertEqual(xr.VERIFIED_BY_VALUES, schema_constraint("observation", "verified_by"))

    def test_type_and_version_are_pinned_to_constants(self):
        for record_type in ("settlement", "observation"):
            self.assertEqual(
                SCHEMA["$defs"][record_type]["properties"]["type"]["const"],
                record_type,
            )
            self.assertEqual(
                SCHEMA["$defs"][record_type]["properties"]["version"]["const"],
                xr.VERSION,
            )

    def test_evidence_and_job_defs_match_module_validation(self):
        self.assertEqual(
            set(SCHEMA["$defs"]["evidence"]["required"]),
            {"room", "seq"},
        )
        self.assertEqual(xr.EVIDENCE_KEYS, set(SCHEMA["$defs"]["evidence"]["properties"]))
        self.assertEqual(xr.JOB_KEYS, set(SCHEMA["$defs"]["job"]["properties"]))
        self.assertEqual({"id"}, set(SCHEMA["$defs"]["job"]["required"]))


if __name__ == "__main__":
    unittest.main()
