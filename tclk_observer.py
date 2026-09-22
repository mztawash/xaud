"""Conservative parsing helpers for tclk/1 room transcripts.

These helpers identify protocol frames and describe what they establish. They do
not claim signature validity or work quality; those require the complete room
record and an independent verifier.
"""

from __future__ import annotations

import json
import base64
import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


TCLK_PREFIX = "tclk1 "
# The public board every offer and accept lands on. Deals normally continue in the
# derived deal room, but the venue can refuse to create one (its room cap), so
# post-accept frames for a contract are also valid here — the state machine tracks
# by contract id and never reads a room name, and live payers run whole deals in
# this room. Refusing them made XAUD blind to exactly the deals that complete.
OFFER_ROOM = "tclk-offers"
KNOWN_FRAME_TYPES = {
    "offer",
    "accept",
    "lock",
    "reveal",
    "refund",
    "cancel",
    "receipt",
    "heartbeat",
}
DID_PATTERN = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
CONTRACT_PATTERN = re.compile(r"^0x[0-9a-f]{64}$")


class TclkFrameError(ValueError):
    """Raised when text is not a valid tclk/1 frame envelope."""


def parse_tclk_frame(text: str) -> dict[str, Any] | None:
    """Parse a tclk/1 frame, returning None for ordinary room text.

    This validates the envelope and identity shape only. Transport signatures,
    canonical JSON bytes, frame-specific guards, and transcript ordering must be
    checked by a complete transcript verifier.
    """
    if not isinstance(text, str) or not text.startswith(TCLK_PREFIX):
        return None

    try:
        frame = json.loads(text[len(TCLK_PREFIX):])
    except json.JSONDecodeError as exc:
        raise TclkFrameError(f"invalid tclk JSON: {exc.msg}") from exc

    if not isinstance(frame, dict):
        raise TclkFrameError("tclk frame must contain a JSON object")

    frame_type = frame.get("type")
    if frame_type not in KNOWN_FRAME_TYPES:
        raise TclkFrameError(f"unknown tclk frame type: {frame_type!r}")

    sender = frame.get("from")
    if not isinstance(sender, str) or not DID_PATTERN.fullmatch(sender):
        raise TclkFrameError("tclk frame requires a full did:key sender")

    contract = frame.get("contract")
    if frame_type == "offer":
        offer_id = frame.get("id")
        if not isinstance(offer_id, str) or not CONTRACT_PATTERN.fullmatch(offer_id):
            raise TclkFrameError("offer requires a contract offer id")
    else:
        if not isinstance(contract, str) or not CONTRACT_PATTERN.fullmatch(contract):
            raise TclkFrameError("non-offer tclk frame requires a contract id")

    return frame


def deal_room(contract: str) -> str:
    """Return the tclk/1 derived deal-room name for a contract id."""
    if not isinstance(contract, str) or not CONTRACT_PATTERN.fullmatch(contract):
        raise ValueError(f"invalid tclk contract id: {contract!r}")
    return f"mb-p-tclk-{contract[2:18]}"


def event_assertion(frame: dict[str, Any]) -> str:
    """Describe the strongest fact established by a parsed frame alone."""
    event = frame["type"]
    return {
        "offer": "job_terms_proposed",
        "accept": "job_accepted",
        "lock": "payment_lock_announced",
        "reveal": "payment_claim_announced",
        "refund": "payment_refunded_or_refund_announced",
        "cancel": "job_cancelled",
        "receipt": "terminal_outcome_acknowledged",
        "heartbeat": "liveness_only",
    }[event]


def is_reputation_evidence(frame: dict[str, Any]) -> bool:
    """Return whether a frame can contribute evidence beyond liveness.

    A complete transcript and a job-quality verifier are still required before
    publishing a verified contribution record.
    """
    return frame["type"] in {"accept", "lock", "reveal", "refund", "cancel", "receipt"}


def _base58_decode(value: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    for char in value:
        number = number * 58 + alphabet.index(char)
    size = (number.bit_length() + 7) // 8
    decoded = number.to_bytes(size, "big") if size else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded


def verify_transport_record(room: str, record: dict[str, Any]) -> bool:
    """Verify the Technocore Ed25519 signature over a complete JSON record."""
    sender = record.get("from")
    nonce = record.get("nonce")
    text = record.get("text")
    signature = record.get("sig")
    if not all(isinstance(value, str) for value in (sender, text, signature)):
        return False
    if nonce is None or not DID_PATTERN.fullmatch(sender):
        return False

    try:
        encoded_key = sender.split("did:key:", 1)[1]
        key_bytes = _base58_decode(encoded_key[1:])
        if key_bytes[:2] != b"\xed\x01" or len(key_bytes) != 34:
            return False
        public_key = Ed25519PublicKey.from_public_bytes(key_bytes[2:])
        signature_bytes = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        public_key.verify(signature_bytes, f"{room}|{nonce}|{text}".encode("utf-8"))
    except (InvalidSignature, ValueError, IndexError, TypeError):
        return False
    return True


def _record_time_ms(record: dict[str, Any]) -> int | None:
    value = record.get("ts", record.get("timestamp"))
    if not isinstance(value, str):
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return None


def order_tclk_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return transcript records in tclk/1 order: offer, accept, post-accept.

    Observation order is not trustworthy. XAUD derives a deal room from the
    contract id the moment a contract appears and may read that room before,
    or interleaved with, the offer/accept it belongs to; it may also re-read a
    room after a restart. The fold requires protocol order and enforces room
    binding, so this only restores order: the first offer, then the first
    accept, then every post-accept record by sequence. Duplicates are dropped.
    """
    offer: dict[str, Any] | None = None
    accept: dict[str, Any] | None = None
    post: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any]] = set()
    for record in records:
        key = (record.get("room"), record.get("seq"))
        if key in seen:
            continue
        seen.add(key)
        try:
            frame = parse_tclk_frame(record.get("text"))
        except (KeyError, TclkFrameError):
            frame = None
        frame_type = frame.get("type") if frame else None
        if frame_type == "offer" and offer is None:
            offer = record
        elif frame_type == "accept" and accept is None:
            accept = record
        else:
            post.append(record)
    post.sort(key=lambda record: record.get("seq", 0))
    ordered: list[dict[str, Any]] = []
    if offer is not None:
        ordered.append(offer)
    if accept is not None:
        ordered.append(accept)
    ordered.extend(post)
    return ordered


def fold_tclk_transcript(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Authenticate and fold a tclk transcript into a terminal verdict.

    Records must include their room name and the complete JSON fields returned
    by Technocore. Any invalid record fails the fold and cannot advance state.
    This implementation verifies hash-lock contracts; point-lock reveals are
    rejected until point-lock verification is implemented here.
    """
    result: dict[str, Any] = {
        "ok": False,
        "verified": False,
        "status": "unknown",
        "reason": "empty transcript",
        "steps": [],
    }
    if not records:
        return result

    state: dict[str, Any] | None = None
    seen_records: set[tuple[str, int]] = set()
    offer: dict[str, Any] | None = None
    offer_id: str | None = None
    contract_id: str | None = None
    offer_room = "tclk-offers"

    for record in records:
        room = record.get("room")
        seq = record.get("seq")
        if not isinstance(room, str) or not isinstance(seq, int):
            result["reason"] = "record is missing room or sequence"
            return result
        record_key = (room, seq)
        if record_key in seen_records:
            result["reason"] = "duplicate transcript record"
            return result
        seen_records.add(record_key)
        if not verify_transport_record(room, record):
            result["reason"] = f"invalid transport signature at {room}:{seq}"
            return result

        try:
            frame = parse_tclk_frame(record["text"])
        except (KeyError, TclkFrameError) as exc:
            result["reason"] = f"invalid tclk frame at {room}:{seq}: {exc}"
            return result
        if frame is None:
            result["reason"] = f"non-tclk record in transcript at {room}:{seq}"
            return result
        if frame["from"] != record["from"]:
            result["reason"] = f"frame sender mismatch at {room}:{seq}"
            return result

        frame_type = frame["type"]
        step = {"type": frame_type, "room": room, "seq": seq, "ok": False}
        result["steps"].append(step)

        if frame_type == "offer":
            if state is not None or room != offer_room:
                step["reason"] = "offer must be the first frame in tclk-offers"
                result["reason"] = step["reason"]
                return result
            offer = frame
            offer_id = frame["id"]
            state = {
                "status": "proposed",
                "payer_did": frame["from"] if frame.get("role") == "payer" else None,
                "payee_did": frame["from"] if frame.get("role") == "payee" else None,
                "lock": frame.get("lock"),
                "statement": None,
                "job": frame.get("job"),
                "offer": frame,
            }
            if state["payer_did"] is None:
                step["reason"] = "offer role must identify the payer"
                result["reason"] = step["reason"]
                return result
            step["ok"] = True
            continue

        if state is None:
            step["reason"] = "frame does not belong to the offered contract"
            result["reason"] = step["reason"]
            return result
        if frame_type in {"accept", "cancel"} and room != offer_room:
            step["reason"] = "accept and cancel must be in tclk-offers"
            result["reason"] = step["reason"]
            return result
        if frame_type not in {"accept", "cancel"} and room not in {deal_room(contract_id), OFFER_ROOM}:
            step["reason"] = "post-accept frame is in the wrong deal room"
            result["reason"] = step["reason"]
            return result

        status = state["status"]
        if frame_type == "accept":
            contract_id = frame.get("contract")
            if (
                status != "proposed"
                or not isinstance(contract_id, str)
                or frame.get("ref") != offer_id
                or frame["from"] == state["payer_did"]
            ):
                step["reason"] = "accept is out of turn or has the wrong counterparty"
            else:
                state["payee_did"] = frame["from"]
                state["statement"] = frame.get("statement")
                state["status"] = "accepted"
                step["ok"] = True
        elif frame_type == "lock":
            if status != "accepted" or frame["from"] != state["payer_did"]:
                step["reason"] = "only the payer may lock an accepted contract"
            else:
                state["status"] = "locked"
                state["rail"] = frame.get("rail")
                state["rail_ref"] = frame.get("ref")
                step["ok"] = True
        elif frame_type == "reveal":
            if status != "locked" or frame["from"] != state["payee_did"]:
                step["reason"] = "only the payee may reveal a locked contract"
            elif state["lock"] != "hash":
                step["reason"] = "point-lock reveal verification is not implemented"
            else:
                secret = frame.get("secret", "")
                statement = state.get("statement", "")
                valid_secret = (
                    isinstance(secret, str)
                    and re.fullmatch(r"0x[0-9a-f]{64}", secret) is not None
                    and isinstance(statement, str)
                    and hashlib.sha256(bytes.fromhex(secret[2:])).hexdigest() == statement[2:]
                )
                if not valid_secret:
                    step["reason"] = "reveal secret does not open the statement"
                else:
                    state["status"] = "claimed"
                    state["secret"] = secret
                    step["ok"] = True
        elif frame_type == "refund":
            if status != "locked" or frame["from"] != state["payer_did"]:
                step["reason"] = "only the payer may refund a locked contract"
            else:
                event_ms = _record_time_ms(record)
                deadline = offer.get("refundAfterMs")
                if event_ms is None or not isinstance(deadline, int) or event_ms < deadline:
                    step["reason"] = "refund arrived before refundAfterMs"
                else:
                    state["status"] = "refunded"
                    step["ok"] = True
        elif frame_type == "cancel":
            if status not in {"proposed", "accepted"} or frame["from"] not in {state["payer_did"], state["payee_did"]}:
                step["reason"] = "cancel is out of turn"
            else:
                state["status"] = "cancelled"
                step["ok"] = True
        elif frame_type == "heartbeat":
            if status not in {"accepted", "locked"} or frame["from"] not in {state["payer_did"], state["payee_did"]}:
                step["reason"] = "heartbeat is not from an active party"
            else:
                step["ok"] = True
        elif frame_type == "receipt":
            expected = {"claimed": "claimed", "refunded": "refunded", "cancelled": "cancelled"}.get(frame.get("outcome"))
            if expected != status:
                step["reason"] = "receipt outcome does not match terminal state"
            else:
                state["receipt"] = frame
                step["ok"] = True

        if not step["ok"]:
            result["reason"] = step.get("reason", "invalid state transition")
            return result

    result.update(state or {})
    result["status"] = state["status"] if state else "unknown"
    result["ok"] = True
    result["verified"] = True
    result["reason"] = "authenticated transcript folded successfully"
    return result


def fold_tclk_lifecycle(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Authenticate the observable lifecycle of a contract with no offer.

    An offer can age out of the firehose before XAUD starts, while its accept
    and post-accept frames are still retained in the derived deal room. The
    terms (amount/asset/job) are then unknowable, but the remaining signed
    frames still establish facts on their own: the accept names the payee and
    carries the statement; the lock names the payer; the reveal opens the
    accepted statement; a cancel names a party; a refund comes from the payer.

    This is the honest partial tier. It returns the same verdict shape as
    ``fold_tclk_transcript`` but never an ``offer``/amount/asset, and callers
    must publish it as ``outcome_verified``, never as a terms-known
    settlement. Point-lock reveals remain unverifiable and are rejected.
    """
    result: dict[str, Any] = {
        "ok": False,
        "verified": False,
        "status": "unknown",
        "reason": "empty transcript",
        "steps": [],
    }
    if not records:
        return result

    state: dict[str, Any] | None = None
    seen_records: set[tuple[str, int]] = set()

    for record in records:
        room = record.get("room")
        seq = record.get("seq")
        if not isinstance(room, str) or not isinstance(seq, int):
            result["reason"] = "record is missing room or sequence"
            return result
        record_key = (room, seq)
        if record_key in seen_records:
            result["reason"] = "duplicate transcript record"
            return result
        seen_records.add(record_key)
        if not verify_transport_record(room, record):
            result["reason"] = f"invalid transport signature at {room}:{seq}"
            return result

        try:
            frame = parse_tclk_frame(record["text"])
        except (KeyError, TclkFrameError) as exc:
            result["reason"] = f"invalid tclk frame at {room}:{seq}: {exc}"
            return result
        if frame is None:
            result["reason"] = f"non-tclk record in transcript at {room}:{seq}"
            return result
        if frame["from"] != record["from"]:
            result["reason"] = f"frame sender mismatch at {room}:{seq}"
            return result

        frame_type = frame["type"]
        step = {"type": frame_type, "room": room, "seq": seq, "ok": False}
        result["steps"].append(step)

        if frame_type == "offer":
            step["reason"] = "lifecycle fold is only for transcripts without an offer"
            result["reason"] = step["reason"]
            return result

        if state is None:
            # The accept is the anchor: it names the payee, the contract, and
            # the statement the reveal must later open.
            if frame_type != "accept" or room != "tclk-offers":
                step["reason"] = "lifecycle must begin at the accepted contract in tclk-offers"
                result["reason"] = step["reason"]
                return result
            contract_id = frame.get("contract")
            if not isinstance(contract_id, str) or not CONTRACT_PATTERN.fullmatch(contract_id):
                step["reason"] = "accept carries no contract id"
                result["reason"] = step["reason"]
                return result
            state = {
                "status": "accepted",
                "contract": contract_id,
                "payee_did": frame["from"],
                "payer_did": None,
                "statement": frame.get("statement"),
                "lock": "hash",
                "job": None,
                "offer": None,
            }
            step["ok"] = True
            continue

        if frame_type == "cancel":
            if room != "tclk-offers":
                step["reason"] = "cancel must be in tclk-offers"
                result["reason"] = step["reason"]
                return result
        elif room not in {deal_room(state["contract"]), OFFER_ROOM}:
            step["reason"] = "post-accept frame is in the wrong deal room"
            result["reason"] = step["reason"]
            return result

        status = state["status"]
        parties = {
            party for party in (state["payer_did"], state["payee_did"]) if party
        }
        if frame_type == "lock":
            if status != "accepted" or frame["from"] == state["payee_did"]:
                step["reason"] = "lock must come from the counterparty after accept"
            else:
                state["payer_did"] = frame["from"]
                state["status"] = "locked"
                state["rail"] = frame.get("rail")
                step["ok"] = True
        elif frame_type == "reveal":
            if status != "locked" or frame["from"] != state["payee_did"]:
                step["reason"] = "only the payee may reveal a locked contract"
            else:
                secret = frame.get("secret", "")
                statement = state.get("statement", "")
                valid_secret = (
                    isinstance(secret, str)
                    and re.fullmatch(r"0x[0-9a-f]{64}", secret) is not None
                    and isinstance(statement, str)
                    and CONTRACT_PATTERN.fullmatch(statement) is not None
                    and hashlib.sha256(bytes.fromhex(secret[2:])).hexdigest() == statement[2:]
                )
                if not valid_secret:
                    step["reason"] = "reveal secret does not open the accepted statement"
                else:
                    state["status"] = "claimed"
                    step["ok"] = True
        elif frame_type == "refund":
            if status != "locked" or frame["from"] != state["payer_did"]:
                step["reason"] = "only the payer may refund a locked contract"
            else:
                # refundAfterMs lived in the unseen offer, so the timing rule
                # cannot be checked here; the payer's signed refund still names
                # the terminal outcome.
                state["status"] = "refunded"
                step["ok"] = True
        elif frame_type == "cancel":
            if status not in {"accepted", "locked"} or frame["from"] not in parties:
                step["reason"] = "cancel is out of turn"
            else:
                state["status"] = "cancelled"
                step["ok"] = True
        elif frame_type == "heartbeat":
            if status not in {"accepted", "locked"} or frame["from"] not in parties:
                step["reason"] = "heartbeat is not from an active party"
            else:
                step["ok"] = True
        elif frame_type == "receipt":
            expected = {"claimed": "claimed", "refunded": "refunded", "cancelled": "cancelled"}.get(frame.get("outcome"))
            if expected != status:
                step["reason"] = "receipt outcome does not match terminal state"
            else:
                step["ok"] = True
        else:
            step["reason"] = f"unexpected lifecycle frame: {frame_type}"

        if not step["ok"]:
            result["reason"] = step.get("reason", "invalid state transition")
            return result

    if state is None:
        result["reason"] = "no accepted contract in transcript"
        return result
    result.update(state)
    result["status"] = state["status"]
    result["ok"] = True
    result["verified"] = True
    result["reason"] = "authenticated lifecycle folded successfully"
    return result
