"""Read-only capture and verification of FLOP Close Call room evidence.

This module never signs or posts messages. It records signed offers/trades and
referee snapshots in XAUD state; only a verified referee flow event can mark a
captured trade settled or void. Public position snapshots are not treated as a
complete account reconciliation source.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tclk_observer import DID_PATTERN, verify_transport_record

SEASON = "close-1"
TRADING_ROOM = "close1"
PRICE_ROOM = "d-close1-price"
POSITIONS_ROOM = "d-close1-positions"
FLOW_ROOM = "d-close1-flow"
MAX_TRADES = 10_000
MAX_SNAPSHOTS = 500
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_NUMERIC = re.compile(r"^(?:0|[1-9]\d*)(?:\.\d+)?$")


def _decode_b58(value: str) -> bytes:
    number = 0
    for char in value:
        number = number * 58 + _B58.index(char)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded


def _public_key(did: str) -> Ed25519PublicKey | None:
    if not isinstance(did, str) or not DID_PATTERN.fullmatch(did):
        return None
    try:
        encoded = _decode_b58(did.split("did:key:", 1)[1][1:])
        if len(encoded) != 34 or encoded[:2] != b"\xed\x01":
            return None
        return Ed25519PublicKey.from_public_bytes(encoded[2:])
    except (ValueError, IndexError):
        return None


def _verify_inner_signature(did: str, signature: Any, canonical: str) -> bool:
    key = _public_key(did)
    if key is None or not isinstance(signature, str):
        return False
    try:
        raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        key.verify(raw, canonical.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _terms_json(terms: dict[str, Any]) -> str:
    return json.dumps(terms, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _is_trade_terms(terms: Any) -> bool:
    if not isinstance(terms, dict):
        return False
    if not all(isinstance(terms.get(key), str) for key in ("id", "maker", "px", "qty", "side")):
        return False
    if terms.get("side") not in ("buy", "sell") or not DID_PATTERN.fullmatch(terms["maker"]):
        return False
    if not _NUMERIC.fullmatch(terms["px"]) or not _NUMERIC.fullmatch(terms["qty"]):
        return False
    try:
        if float(terms["px"]) <= 0 or float(terms["qty"]) <= 0:
            return False
    except ValueError:
        return False
    return isinstance(terms.get("until"), int) and not isinstance(terms.get("until"), bool)


def _verified_transport(room: str, message: dict[str, Any]) -> bool:
    # The main agent's parsed shape uses both `sender` and `from`; keep this
    # observer usable with either the parser's full record or raw API records.
    record = dict(message)
    record.setdefault("from", record.get("sender"))
    if "ts" not in record:
        record["ts"] = record.get("timestamp")
    return verify_transport_record(room, record)


def _append_bounded(items: list, item: dict, limit: int = MAX_SNAPSHOTS) -> None:
    items.append(item)
    del items[:-limit]


def _ensure_capture(state: dict[str, Any]) -> dict[str, Any]:
    capture = state.setdefault("close_call_capture", {})
    capture.setdefault("trades", {})
    capture.setdefault("outcomes", {})
    capture.setdefault("offers", {})
    capture.setdefault("prices", [])
    capture.setdefault("positions", [])
    capture.setdefault("rejected", 0)
    return capture


def _apply_outcome(capture: dict[str, Any], trade_id: str, outcome: dict[str, Any]) -> None:
    previous = capture["outcomes"].get(trade_id)
    if previous and previous.get("authority_verified") and not outcome.get("authority_verified"):
        return
    capture["outcomes"][trade_id] = outcome
    trade = capture["trades"].get(trade_id)
    if trade is not None:
        trade["status"] = (
            outcome["status"] if outcome.get("authority_verified")
            else f"flow_reported_{outcome['status']}"
        )
        trade["outcome_evidence"] = outcome["evidence"]


def observe_message(state: dict[str, Any], room: str, message: dict[str, Any]) -> str | None:
    """Capture a recognized Close Call record; return its verdict or None.

    A recognized-but-invalid room record returns ``rejected`` and is never
    stored as trade/referee evidence. Non-Close-Call messages return ``None``.
    """
    if room not in (TRADING_ROOM, PRICE_ROOM, POSITIONS_ROOM, FLOW_ROOM):
        return None
    try:
        payload = json.loads(message.get("text", ""))
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    kind = payload.get("t")
    recognized = (
        (room == TRADING_ROOM and kind in ("owner", "offer", "trade"))
        or (room == PRICE_ROOM and kind in ("seed", "price"))
        or (room == POSITIONS_ROOM and kind == "positions")
        or (room == FLOW_ROOM and kind == "flow")
    )
    if not recognized:
        return None

    capture = _ensure_capture(state)
    if payload.get("season", SEASON) != SEASON or not _verified_transport(room, message):
        capture["rejected"] += 1
        return "rejected"

    sender = message.get("from", message.get("sender"))
    seq = message.get("seq")
    evidence = {
        "room": room,
        "seq": seq,
        "sender": sender,
        "text_sha256": hashlib.sha256(message["text"].encode("utf-8")).hexdigest(),
        "transport_signature_verified": True,
    }

    if room == TRADING_ROOM and kind == "offer":
        terms = payload.get("terms")
        if not _is_trade_terms(terms) or terms.get("maker") != sender:
            capture["rejected"] += 1
            return "rejected"
        canonical = f"{SEASON}|terms|{_terms_json(terms)}"
        if not _verify_inner_signature(sender, payload.get("maker_sig"), canonical):
            capture["rejected"] += 1
            return "rejected"
        offer_id = terms["id"]
        capture["offers"].setdefault(offer_id, {
            "terms": terms,
            "maker": sender,
            "evidence": evidence,
            "status": "offered",
        })
        while len(capture["offers"]) > MAX_TRADES:
            capture["offers"].pop(next(iter(capture["offers"])))
        return "offer"

    if room == TRADING_ROOM and kind == "trade":
        terms = payload.get("terms")
        maker = terms.get("maker") if isinstance(terms, dict) else None
        taker = payload.get("taker")
        if not _is_trade_terms(terms) or not isinstance(taker, str) or not DID_PATTERN.fullmatch(taker):
            capture["rejected"] += 1
            return "rejected"
        if sender != taker:
            capture["rejected"] += 1
            return "rejected"
        canonical_terms = _terms_json(terms)
        maker_ok = _verify_inner_signature(maker, payload.get("maker_sig"), f"{SEASON}|terms|{canonical_terms}")
        taker_ok = _verify_inner_signature(taker, payload.get("taker_sig"), f"{SEASON}|accept|{canonical_terms}|{taker}")
        if not maker_ok or not taker_ok:
            capture["rejected"] += 1
            return "rejected"
        trade_id = terms["id"]
        if trade_id not in capture["trades"]:
            outcome = capture["outcomes"].get(trade_id, {})
            outcome_status = outcome.get("status", "observed")
            if outcome_status != "observed" and not outcome.get("authority_verified"):
                outcome_status = f"flow_reported_{outcome_status}"
            capture["trades"][trade_id] = {
                "id": trade_id,
                "maker": maker,
                "taker": taker,
                "terms": terms,
                "side": terms["side"],
                "price": terms["px"],
                "qty": terms["qty"],
                "sweep_until": terms["until"],
                "status": outcome_status,
                "evidence": evidence,
                "outcome_evidence": outcome.get("evidence"),
                "maker_signature_verified": True,
                "taker_signature_verified": True,
            }
            while len(capture["trades"]) > MAX_TRADES:
                capture["trades"].pop(next(iter(capture["trades"])))
        return "trade"

    if room == PRICE_ROOM and kind in ("seed", "price"):
        try:
            sweep = int(payload["for"] if kind == "seed" else payload["n"])
            price = float(payload["price"] if kind == "seed" else payload["ref"]["px"])
            limits = payload["limits"]
            lower, upper = float(limits[0]), float(limits[1])
            if sweep < 0 or price <= 0 or lower <= 0 or upper < lower:
                raise ValueError("invalid price snapshot")
        except (KeyError, TypeError, ValueError, IndexError):
            capture["rejected"] += 1
            return "rejected"
        _append_bounded(capture["prices"], {
            "sweep": sweep, "price": price, "lower": lower, "upper": upper,
            "evidence": evidence,
        })
        return "price"

    if room == POSITIONS_ROOM:
        if not isinstance(payload.get("top"), list):
            capture["rejected"] += 1
            return "rejected"
        _append_bounded(capture["positions"], {
            "snapshot_type": "public_top_positions",
            "top": payload["top"],
            "evidence": evidence,
        })
        return "positions"

    if room == FLOW_ROOM:
        settled = payload.get("settled", [])
        void = payload.get("void", [])
        if not isinstance(settled, list) or not isinstance(void, list):
            capture["rejected"] += 1
            return "rejected"
        configured_referee = os.environ.get("CLOSE_CALL_REFEREE_DID", "").strip()
        authority_verified = bool(
            configured_referee
            and DID_PATTERN.fullmatch(configured_referee)
            and sender == configured_referee
        )
        for trade_id in settled:
            if isinstance(trade_id, str):
                _apply_outcome(capture, trade_id, {
                    "status": "settled",
                    "authority_verified": authority_verified,
                    "evidence": evidence,
                })
        for item in void:
            if isinstance(item, (list, tuple)) and len(item) >= 2 and isinstance(item[0], str):
                _apply_outcome(capture, item[0], {
                    "status": "void",
                    "authority_verified": authority_verified,
                    "reason": str(item[1]),
                    "evidence": evidence,
                })
        while len(capture["outcomes"]) > MAX_TRADES:
            capture["outcomes"].pop(next(iter(capture["outcomes"])))
        return "flow"

    if room == TRADING_ROOM and kind == "owner":
        return "owner"
    return None