"""Canonical xaud1 registry-record frames.

XAUD publishes one canonical frame per verified event into /r/xaud. The wire
rules mirror tclk/1 so that stored bytes equal signed bytes and any reader can
decode deterministically:

- a record is the prefix ``xaud1 `` followed by one JSON object,
- serialized canonically: object keys sorted, ``,``/``:`` separators only,
  every non-ASCII character ``\\uXXXX``-escaped (ASCII-only, single line),
- decoding is fail-closed: a known record type with an unknown key, a missing
  field, or a malformed value is rejected, never coerced.

Record kinds:

- ``settlement``  -- a pairwise transaction verified from a folded tclk
  transcript (``verified_by: transcript``). Names both parties, the contract
  and outcome. ``status: terms_verified`` carries the amount and asset
  (the full terms were observed); ``status: outcome_verified`` omits them
  because the offer aged out before XAUD started, so only the payer, payee,
  contract and terminal outcome are provable. This proves the payment
  lifecycle completed; it never claims work quality.
- ``observation`` -- a claimed contribution observed in a room
  (status ``observed``, ``verified_by: none``). Carries the subject's exact
  words verbatim; XAUD does not judge it.

The legacy ``agent_did=... key=value`` records already in /r/xaud remain
readable through :func:`parse_legacy_registry_record`.
"""

from __future__ import annotations

import json
import re
from typing import Any

from contribution_registry import ACTIVITY_TYPES
from tclk_observer import CONTRACT_PATTERN, DID_PATTERN


XAUD_PREFIX = "xaud1 "
VERSION = "xaud1"

RECORD_TYPES = {"settlement", "observation"}

OUTCOMES = {"claimed", "refunded", "cancelled"}
SETTLEMENT_STATUSES = {"terms_verified", "outcome_verified"}
# Statuses published before the terms/outcome split. They are parsed as the
# terms-known tier so the records already in /r/xaud keep decoding.
LEGACY_SETTLEMENT_STATUSES = {"transcript_verified": "terms_verified"}
ALL_SETTLEMENT_STATUSES = SETTLEMENT_STATUSES | set(LEGACY_SETTLEMENT_STATUSES)
OBSERVATION_STATUSES = {"observed", "work_verified", "failed", "disputed"}
VERIFIED_BY_VALUES = {"transcript", "attestation", "arbiter", "none"}
OBSERVATION_IDENTITY_STATUSES = {"identified", "unresolved_sender"}

JOB_KEYS = {"id", "proto", "context"}
EVIDENCE_KEYS = {"room", "seq", "offer_room", "offer_seq"}

AMOUNT_PATTERN = re.compile(r"^[0-9]+$")
RAIL_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
ASSET_PATTERN = re.compile(r"^\S{1,32}$")
ROOM_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")

# One source of truth for the field contract. schema/xaud1-records.schema.json
# mirrors these sets; tests/test_xaud_records.py pins the two together so they
# cannot drift.
REQUIRED_FIELDS = {
    "settlement": {
        "type", "version", "contract", "payer", "payee",
        "outcome", "status", "verified_by", "evidence",
    },
    "observation": {
        "type", "version", "status", "identity_status", "evidence", "summary",
    },
}

OPTIONAL_FIELDS = {
    "settlement": {"amount", "asset", "rail", "job", "job_summary", "summary"},
    "observation": {
        "agent_did", "sender", "task", "activity_type", "score", "tags",
        "verified_by",
    },
}

# Technocore single-line message cap; a canonical frame must fit in one write.
MAX_FRAME_CHARS = 4096


class XaudRecordError(ValueError):
    """Raised when text is not a valid xaud1 registry record."""


# ============================================================
# CANONICAL ENCODING
# ============================================================

def encode_frame(frame: dict[str, Any]) -> str:
    """Encode a frame as canonical single-line XAUD text.

    ASCII-escaped output is load-bearing: the server sweeps Cc/Cf/Cs/Co
    characters to spaces on write, so a raw control character in the payload
    would make the stored bytes differ from the signed bytes. With
    ``ensure_ascii=True`` the emitted text is pure ASCII and single-line, so
    stored bytes always equal signed bytes.
    """
    if not isinstance(frame, dict):
        raise XaudRecordError("xaud1 record must be a JSON object")
    return XAUD_PREFIX + json.dumps(
        frame, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _check_length(text: str) -> str:
    if len(text) > MAX_FRAME_CHARS:
        raise XaudRecordError(
            f"xaud1 frame is {len(text)} chars; room message cap is {MAX_FRAME_CHARS}"
        )
    return text


# ============================================================
# SHARED VALIDATORS
# ============================================================

def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_str(frame: dict[str, Any], field: str) -> str:
    value = frame.get(field)
    if not isinstance(value, str) or not value.strip():
        raise XaudRecordError(f"{field} is required")
    return value


def _validate_did_field(frame: dict[str, Any], field: str) -> None:
    value = frame.get(field)
    if not isinstance(value, str) or not DID_PATTERN.fullmatch(value):
        raise XaudRecordError(f"{field} must be a full did:key")


def _validate_contract(frame: dict[str, Any]) -> None:
    value = frame.get("contract")
    if not isinstance(value, str) or not CONTRACT_PATTERN.fullmatch(value):
        raise XaudRecordError("contract must be a tclk contract id")


def _validate_job(frame: dict[str, Any]) -> None:
    """Validate the optional job binding; the id is the only hard field."""
    job = frame.get("job")
    if job is None:
        return
    if not isinstance(job, dict):
        raise XaudRecordError("job must be a JSON object")
    unknown = set(job) - JOB_KEYS
    if unknown:
        raise XaudRecordError(f"job has unknown fields: {sorted(unknown)}")
    if not isinstance(job.get("id"), str) or not job["id"].strip():
        raise XaudRecordError("job.id is required when job is present")
    if "proto" in job and (not isinstance(job["proto"], str) or not job["proto"].strip()):
        raise XaudRecordError("job.proto must be a non-empty string")
    # job.context is external vocabulary; any shape is preserved verbatim.


def _validate_evidence(frame: dict[str, Any]) -> None:
    evidence = frame.get("evidence")
    if not isinstance(evidence, dict):
        raise XaudRecordError("evidence must be a JSON object")
    unknown = set(evidence) - EVIDENCE_KEYS
    if unknown:
        raise XaudRecordError(f"evidence has unknown fields: {sorted(unknown)}")
    room = evidence.get("room")
    if not isinstance(room, str) or not ROOM_PATTERN.fullmatch(room):
        raise XaudRecordError("evidence.room must be a room name")
    if not _is_int(evidence.get("seq")) or evidence["seq"] < 0:
        raise XaudRecordError("evidence.seq must be a non-negative integer")
    for field in ("offer_room", "offer_seq"):
        if field in evidence and evidence[field] is not None:
            if field == "offer_room" and (
                not isinstance(evidence[field], str)
                or not ROOM_PATTERN.fullmatch(evidence[field])
            ):
                raise XaudRecordError(f"evidence.{field} must be a room name")
            if field == "offer_seq" and (
                not _is_int(evidence[field]) or evidence[field] < 0
            ):
                raise XaudRecordError(f"evidence.{field} must be a non-negative integer")


def _require_exactly_one(frame: dict[str, Any], fields: tuple[str, ...], label: str) -> None:
    present = [field for field in fields if frame.get(field) is not None]
    if len(present) != 1:
        raise XaudRecordError(f"{label} requires exactly one of {fields}")


def _reject_unknown_keys(frame: dict[str, Any], record_type: str) -> None:
    allowed = REQUIRED_FIELDS[record_type] | OPTIONAL_FIELDS[record_type]
    unknown = set(frame) - allowed
    if unknown:
        raise XaudRecordError(
            f"unknown {record_type} field(s): {sorted(unknown)}"
        )


# ============================================================
# PER-TYPE VALIDATION
# ============================================================

def canonical_settlement_status(status: Any) -> Any:
    """Map a legacy settlement status onto the current terms/outcome tier."""
    return LEGACY_SETTLEMENT_STATUSES.get(status, status)


def validate_settlement(frame: dict[str, Any]) -> None:
    """Validate a settlement record (verified pairwise transaction).

    Amount and asset are required only for the terms-known tier; an
    ``outcome_verified`` record carries neither because the offer that held
    them was never observed.
    """
    _reject_unknown_keys(frame, "settlement")
    for field in ("contract", "payer", "payee"):
        _require_str(frame, field)
    _validate_contract(frame)
    _validate_did_field(frame, "payer")
    _validate_did_field(frame, "payee")
    if frame["payer"] == frame["payee"]:
        raise XaudRecordError("payer and payee must be different DIDs")
    if frame.get("outcome") not in OUTCOMES:
        raise XaudRecordError(f"outcome must be one of {sorted(OUTCOMES)}")
    status = canonical_settlement_status(frame.get("status"))
    if status not in SETTLEMENT_STATUSES:
        raise XaudRecordError(
            f"settlement status must be one of {sorted(ALL_SETTLEMENT_STATUSES)}"
        )
    if status == "terms_verified":
        for field in ("amount", "asset"):
            _require_str(frame, field)
        if not AMOUNT_PATTERN.fullmatch(frame["amount"]):
            raise XaudRecordError("amount must be a decimal integer string")
        if not ASSET_PATTERN.fullmatch(frame["asset"]):
            raise XaudRecordError("asset must be a single token, 1-32 chars")
    else:
        # A partial record must not smuggle in terms it cannot prove.
        for field in ("amount", "asset"):
            if frame.get(field) is not None:
                raise XaudRecordError(
                    f"{field} is not allowed on an outcome_verified settlement"
                )
    if frame.get("verified_by") != "transcript":
        raise XaudRecordError("settlement verified_by must be 'transcript'")
    if "rail" in frame and frame["rail"] is not None:
        rail = frame["rail"]
        if not isinstance(rail, str) or not RAIL_PATTERN.fullmatch(rail):
            raise XaudRecordError(f"invalid rail id: {rail!r}")
    _validate_job(frame)
    _validate_evidence(frame)
    if "job_summary" in frame:
        if not isinstance(frame["job_summary"], str) or not frame["job_summary"].strip():
            raise XaudRecordError("job_summary must be a non-empty string")


def validate_observation(frame: dict[str, Any]) -> None:
    """Validate an observation record (claimed, never judged)."""
    _reject_unknown_keys(frame, "observation")
    # evidence is a nested object, validated by _validate_evidence below.
    for field in ("status", "identity_status", "summary"):
        _require_str(frame, field)
    if frame.get("status") not in OBSERVATION_STATUSES:
        raise XaudRecordError(
            f"observation status must be one of {sorted(OBSERVATION_STATUSES)}"
        )
    if frame.get("identity_status") not in OBSERVATION_IDENTITY_STATUSES:
        raise XaudRecordError(
            "identity_status must be 'identified' or 'unresolved_sender'"
        )
    verified_by = frame.get("verified_by", "none")
    if verified_by not in VERIFIED_BY_VALUES:
        raise XaudRecordError(f"verified_by must be one of {sorted(VERIFIED_BY_VALUES)}")
    if frame["identity_status"] == "identified":
        _require_exactly_one(frame, ("agent_did", "sender"), "identified observation")
        _validate_did_field(frame, "agent_did")
    else:
        _require_exactly_one(frame, ("agent_did", "sender"), "observation")
        if not isinstance(frame.get("sender"), str) or not frame["sender"].strip():
            raise XaudRecordError("sender must be a non-empty sender reference")
    if "task" in frame and (not isinstance(frame["task"], str) or not frame["task"].strip()):
        raise XaudRecordError("task must be a non-empty string")
    if "activity_type" in frame and frame["activity_type"] not in ACTIVITY_TYPES:
        raise XaudRecordError(
            f"activity_type must be one of {sorted(ACTIVITY_TYPES)}"
        )
    if "score" in frame:
        score = frame["score"]
        if not _is_int(score) or not 0 <= score <= 20:
            raise XaudRecordError("score must be an integer from 0 to 20")
    if "tags" in frame:
        tags = frame["tags"]
        if (
            not isinstance(tags, list)
            or not all(isinstance(tag, str) and tag.strip() for tag in tags)
        ):
            raise XaudRecordError("tags must be a list of non-empty strings")
    _validate_evidence(frame)


# ============================================================
# PARSE
# ============================================================

def parse_xaud_record(text: str) -> dict[str, Any] | None:
    """Parse and validate an xaud1 registry record.

    Returns None for ordinary room text. Raises XaudRecordError for text that
    carries the xaud1 prefix but is not a valid registry record (including
    work_attestation frames, which belong to xaud_attestation).
    """
    if not isinstance(text, str) or not text.startswith(XAUD_PREFIX):
        return None
    try:
        frame = json.loads(text[len(XAUD_PREFIX):])
    except json.JSONDecodeError as exc:
        raise XaudRecordError(f"invalid xaud1 JSON: {exc.msg}") from exc

    if not isinstance(frame, dict):
        raise XaudRecordError("xaud1 record must be a JSON object")
    if frame.get("version") != VERSION:
        raise XaudRecordError(f"unsupported xaud1 version: {frame.get('version')!r}")
    record_type = frame.get("type")
    if record_type not in RECORD_TYPES:
        raise XaudRecordError(f"unsupported xaud1 record type: {record_type!r}")

    if record_type == "settlement":
        validate_settlement(frame)
    else:
        validate_observation(frame)
    return frame


# ============================================================
# BUILDERS
# ============================================================

def build_settlement_frame(
    *,
    contract: str,
    payer: str,
    payee: str,
    amount: str | None = None,
    asset: str | None = None,
    outcome: str = "claimed",
    status: str = "terms_verified",
    rail: str | None = None,
    job: dict[str, Any] | None = None,
    job_summary: str | None = None,
    summary: str | None = None,
    evidence_room: str,
    evidence_seq: int,
    offer_room: str | None = None,
    offer_seq: int | None = None,
) -> str:
    """Build a canonical settlement frame for a verified tclk transaction.

    ``status="terms_verified"`` names the amount and asset (the full terms
    were in the observed offer); ``status="outcome_verified"`` omits them
    (the offer was never observed).
    """
    frame: dict[str, Any] = {
        "type": "settlement",
        "version": VERSION,
        "contract": contract,
        "payer": payer,
        "payee": payee,
        "outcome": outcome,
        "status": status,
        "verified_by": "transcript",
        "evidence": {"room": evidence_room, "seq": evidence_seq},
    }
    if amount is not None:
        frame["amount"] = str(amount)
    if asset is not None:
        frame["asset"] = asset
    if rail is not None:
        frame["rail"] = rail
    if job is not None:
        frame["job"] = job
    if job_summary:
        frame["job_summary"] = job_summary
    if summary:
        frame["summary"] = summary
    if offer_room is not None:
        frame["evidence"]["offer_room"] = offer_room
    if offer_seq is not None:
        frame["evidence"]["offer_seq"] = offer_seq
    validate_settlement(frame)
    return _check_length(encode_frame(frame))


def build_observation_frame(
    *,
    evidence_room: str,
    evidence_seq: int,
    summary: str,
    status: str = "observed",
    identity_status: str = "identified",
    verified_by: str = "none",
    agent_did: str | None = None,
    sender: str | None = None,
    task: str | None = None,
    activity_type: str | None = None,
    score: int | None = None,
    tags: list[str] | None = None,
    offer_room: str | None = None,
    offer_seq: int | None = None,
) -> str:
    """Build a canonical observation frame for a claimed contribution."""
    frame: dict[str, Any] = {
        "type": "observation",
        "version": VERSION,
        "status": status,
        "identity_status": identity_status,
        "verified_by": verified_by,
        "evidence": {"room": evidence_room, "seq": evidence_seq},
        "summary": summary,
    }
    if identity_status == "identified":
        frame["agent_did"] = agent_did
    else:
        frame["sender"] = sender
    if task is not None:
        frame["task"] = task
    if activity_type is not None:
        frame["activity_type"] = activity_type
    if score is not None:
        frame["score"] = score
    if tags is not None:
        frame["tags"] = tags
    if offer_room is not None:
        frame["evidence"]["offer_room"] = offer_room
    if offer_seq is not None:
        frame["evidence"]["offer_seq"] = offer_seq
    validate_observation(frame)
    return _check_length(encode_frame(frame))


# ============================================================
# LEGACY READS
# ============================================================

_LEGACY_FIELD = re.compile(r"([a-z_]+)=([^ =]+)")


def parse_legacy_registry_record(text: str) -> dict[str, Any] | None:
    """Best-effort parse of a legacy ``agent_did=...`` key=value record.

    Records published before the xaud1 canonical format are single-line
    space-separated ``key=value`` fields with a free-text ``summary`` tail.
    This reader normalizes them into the observation shape so old records stay
    replayable. Returns None when the line is not a legacy registry record.
    """
    if not isinstance(text, str) or "agent_did=" not in text:
        return None
    head, _, summary = text.partition(" summary=")
    fields: dict[str, str] = {}
    for key, value in _LEGACY_FIELD.findall(head):
        fields.setdefault(key, value)
    if not fields.get("agent_did"):
        return None
    record: dict[str, Any] = {
        "type": "observation",
        "version": "xaud0",
        "status": fields.get("status", "observed"),
        "identity_status": fields.get("identity_status", "identified"),
        "evidence": fields.get("evidence", ""),
        "summary": summary if summary else fields.get("summary", ""),
    }
    agent_did = fields.get("agent_did", "")
    if DID_PATTERN.fullmatch(agent_did):
        record["agent_did"] = agent_did
    else:
        record["sender"] = agent_did
    for field in ("task", "activity_type"):
        if fields.get(field):
            record[field] = fields[field]
    if fields.get("score") is not None:
        try:
            record["score"] = int(fields["score"])
        except ValueError:
            pass
    tags = fields.get("tags")
    if tags and tags != "none":
        record["tags"] = [tag for tag in tags.split(",") if tag]
    return record
