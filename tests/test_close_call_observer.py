import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import close_call_observer as observer
from sign import did_of, load_key, signature


def signed_message(room, seq, payload, key):
    text = json.dumps(payload, separators=(",", ":"))
    nonce = str(5000 + seq)
    sender = did_of(key)
    return {
        "seq": seq,
        "timestamp": "2026-10-03T12:00:00Z",
        "sender": sender,
        "from": sender,
        "nonce": nonce,
        "text": text,
        "sig": signature(key, f"{room}|{nonce}|{text}"),
    }


class CloseCallObserverTests(unittest.TestCase):
    def setUp(self):
        self.maker_key, _ = load_key("close-call-maker-test")
        self.taker_key, _ = load_key("close-call-taker-test")
        self.referee_key, _ = load_key("close-call-referee-test")
        self.maker = did_of(self.maker_key)
        self.taker = did_of(self.taker_key)
        self.state = {}
        self.terms = {
            "id": "challenge-trade-1",
            "maker": self.maker,
            "px": "215.20",
            "qty": "0.10",
            "side": "buy",
            "taker": "any",
            "until": 42,
        }
        canonical = json.dumps(self.terms, sort_keys=True, separators=(",", ":"))
        self.trade = {
            "season": "close-1",
            "t": "trade",
            "terms": self.terms,
            "maker_sig": signature(self.maker_key, f"close-1|terms|{canonical}"),
            "taker": self.taker,
            "taker_sig": signature(self.taker_key, f"close-1|accept|{canonical}|{self.taker}"),
        }

    def test_captures_dual_signed_trade_and_verified_flow_settlement(self):
        trade_message = signed_message("close1", 10, self.trade, self.taker_key)
        self.assertEqual(observer.observe_message(self.state, "close1", trade_message), "trade")
        captured = self.state["close_call_capture"]["trades"]["challenge-trade-1"]
        self.assertEqual(captured["status"], "observed")
        self.assertTrue(captured["maker_signature_verified"])
        self.assertTrue(captured["taker_signature_verified"])

        flow = signed_message("d-close1-flow", 11, {
            "t": "flow", "n": 42, "settled": ["challenge-trade-1"], "void": [],
        }, self.referee_key)
        self.assertEqual(observer.observe_message(self.state, "d-close1-flow", flow), "flow")
        self.assertEqual(captured["status"], "flow_reported_settled")
        self.assertEqual(captured["outcome_evidence"]["room"], "d-close1-flow")

    def test_records_flow_outcome_arriving_before_trade(self):
        flow = signed_message("d-close1-flow", 12, {
            "t": "flow", "n": 42, "settled": [],
            "void": [["challenge-trade-1", "outside-band"]],
        }, self.referee_key)
        observer.observe_message(self.state, "d-close1-flow", flow)
        observer.observe_message(self.state, "close1", signed_message("close1", 13, self.trade, self.taker_key))
        trade = self.state["close_call_capture"]["trades"]["challenge-trade-1"]
        self.assertEqual(trade["status"], "flow_reported_void")
        self.assertEqual(self.state["close_call_capture"]["outcomes"]["challenge-trade-1"]["reason"], "outside-band")

    def test_configured_referee_identity_confirms_flow_outcome(self):
        flow = signed_message("d-close1-flow", 18, {
            "t": "flow", "n": 42, "settled": ["challenge-trade-1"], "void": [],
        }, self.referee_key)
        with mock.patch.dict(os.environ, {"CLOSE_CALL_REFEREE_DID": did_of(self.referee_key)}):
            observer.observe_message(self.state, "d-close1-flow", flow)
        observer.observe_message(self.state, "close1", signed_message("close1", 19, self.trade, self.taker_key))
        trade = self.state["close_call_capture"]["trades"]["challenge-trade-1"]
        self.assertEqual(trade["status"], "settled")
        self.assertTrue(self.state["close_call_capture"]["outcomes"]["challenge-trade-1"]["authority_verified"])

    def test_unconfigured_report_cannot_downgrade_verified_outcome(self):
        flow = signed_message("d-close1-flow", 20, {
            "t": "flow", "n": 42, "settled": ["challenge-trade-1"], "void": [],
        }, self.referee_key)
        with mock.patch.dict(os.environ, {"CLOSE_CALL_REFEREE_DID": did_of(self.referee_key)}):
            observer.observe_message(self.state, "d-close1-flow", flow)
        later_report = signed_message("d-close1-flow", 21, {
            "t": "flow", "n": 43, "settled": [],
            "void": [["challenge-trade-1", "reported-void"]],
        }, self.taker_key)
        with mock.patch.dict(os.environ, {}, clear=True):
            observer.observe_message(self.state, "d-close1-flow", later_report)
        self.assertEqual(
            self.state["close_call_capture"]["outcomes"]["challenge-trade-1"]["status"],
            "settled",
        )

    def test_rejects_tampered_inner_signature_even_with_valid_transport(self):
        tampered = {**self.trade, "taker_sig": "not-a-valid-signature"}
        message = signed_message("close1", 14, tampered, self.taker_key)
        self.assertEqual(observer.observe_message(self.state, "close1", message), "rejected")
        self.assertEqual(self.state["close_call_capture"]["trades"], {})
        self.assertEqual(self.state["close_call_capture"]["rejected"], 1)

    def test_rejects_tampered_transport_record(self):
        message = signed_message("close1", 15, self.trade, self.taker_key)
        message["text"] += " "
        self.assertEqual(observer.observe_message(self.state, "close1", message), "rejected")
        self.assertEqual(self.state["close_call_capture"]["trades"], {})

    def test_captures_price_and_marks_positions_as_public_top_only(self):
        price = signed_message("d-close1-price", 16, {
            "t": "price", "n": 42, "ref": {"px": "215.20"}, "limits": [204.44, 225.96],
        }, self.referee_key)
        self.assertEqual(observer.observe_message(self.state, "d-close1-price", price), "price")
        positions = signed_message("d-close1-positions", 17, {
            "t": "positions", "top": [[self.taker, "0.10"]],
        }, self.referee_key)
        self.assertEqual(observer.observe_message(self.state, "d-close1-positions", positions), "positions")
        capture = self.state["close_call_capture"]
        self.assertEqual(capture["prices"][0]["price"], 215.2)
        self.assertEqual(capture["positions"][0]["snapshot_type"], "public_top_positions")

    def test_ignores_non_close_call_room(self):
        self.assertIsNone(observer.observe_message(self.state, "lobby", {"text": "hello"}))
        self.assertNotIn("close_call_capture", self.state)


if __name__ == "__main__":
    unittest.main()