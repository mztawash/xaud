"""Signed XAUD work-attestation frames.

An attestation is an evaluator's claim about a completed job. It is separate
from tclk settlement: payment proves a lifecycle outcome, while this frame
records an independent quality verdict.
"""

from __future__ import annotations

import json
import re
from typing import Any

from tclk_observer import DID_PATTERN, verify_transport_record


XAUD_PREFIX = "xaud1 "
ATTESTATION_TYPE = "work_attestation"
VERDICTS = {"passed", "failed", "disputed"}
TASK_TYPES = {
    "builder",
    "trading",
    "collaboration",
    "audit",
    "research",
    "documentation",
    "identity",
    "network",
    "agent-ops",
    "general",
}
CONTRACT_PATTERN = re.compile(r"^0x[0-9a-f]{64}$")


class AttestationError(ValueError):
    """Raised when an XAUD attestation is malformed or unsafe."""


def encode_attestation(frame: dict[str, Any]) -> str:
    """Encode an attestation as canonical single-line XAUD text."""
    return XAUD_PREFIX + json.dumps(frame, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def build_attestation_frame(
    *,
    agent_did: str,
    evaluator_did: str,
    contract: str,
    job_id: str,
    task_type: str,
    verdict: str,
    criteria: str,
    evidence: list[str],
    summary: str,
    nonce: str,
) -> str:
    """Build an evaluator-signed payload ready for a signed room post."""
    frame = {
        "agent_did": agent_did,
        "contract": contract,
        "criteria": criteria,
        "evaluator_did": evaluator_did,
        "evidence": evidence,
        "job_id": job_id,
        "nonce": nonce,
        "summary": summary,
        "task_type": task_type,
        "type": ATTESTATION_TYPE,
        "verdict": verdict,
        "version": "xaud1",
    }
    validate_attestation(frame)
    return encode_attestation(frame)


def parse_attestation(text: str) -> dict[str, Any] | None:
    """Parse and validate an XAUD frame, or return None for other text."""
    if not isinstance(text, str) or not text.startswith(XAUD_PREFIX):
        return None
    try:
        frame = json.loads(text[len(XAUD_PREFIX):])
    except json.JSONDecodeError as exc:
        raise AttestationError(f"invalid XAUD JSON: {exc.msg}") from exc
    validate_attestation(frame)
    return frame


def validate_attestation(frame: dict[str, Any]) -> None:
    """Validate attestation structure and anti-self-certification rules."""
    if not isinstance(frame, dict):
        raise AttestationError("attestation must be a JSON object")
    if frame.get("version") != "xaud1" or frame.get("type") != ATTESTATION_TYPE:
        raise AttestationError("unsupported XAUD attestation version or type")
    for field in ("agent_did", "evaluator_did"):
        if not isinstance(frame.get(field), str) or not DID_PATTERN.fullmatch(frame[field]):
            raise AttestationError(f"{field} must be a full did:key")
    if frame["agent_did"] == frame["evaluator_did"]:
        raise AttestationError("agent cannot evaluate its own work")
    if not isinstance(frame.get("contract"), str) or not CONTRACT_PATTERN.fullmatch(frame["contract"]):
        raise AttestationError("contract must be a tclk contract id")
    if not isinstance(frame.get("job_id"), str) or not frame["job_id"].strip():
        raise AttestationError("job_id is required")
    if frame.get("task_type") not in TASK_TYPES:
        raise AttestationError("unknown task_type")
    if frame.get("verdict") not in VERDICTS:
        raise AttestationError("verdict must be passed, failed, or disputed")
    if not isinstance(frame.get("criteria"), str) or not frame["criteria"].strip():
        raise AttestationError("criteria is required")
    if not isinstance(frame.get("summary"), str) or not frame["summary"].strip():
        raise AttestationError("summary is required")
    evidence = frame.get("evidence")
    if not isinstance(evidence, list) or not evidence or not all(isinstance(item, str) and item.strip() for item in evidence):
        raise AttestationError("at least one evidence reference is required")
    if not isinstance(frame.get("nonce"), str) or not frame["nonce"].strip():
        raise AttestationError("nonce is required")


def verify_attestation_record(room: str, record: dict[str, Any]) -> dict[str, Any]:
    """Verify transport authorship and return a normalized attestation verdict."""
    try:
        frame = parse_attestation(record.get("text", ""))
    except AttestationError as exc:
        return {"verified": False, "reason": str(exc)}
    if frame is None:
        return {"verified": False, "reason": "not an XAUD attestation"}
    if not verify_transport_record(room, record):
        return {"verified": False, "reason": "invalid evaluator transport signature"}
    if record.get("from") != frame["evaluator_did"]:
        return {"verified": False, "reason": "transport signer is not evaluator_did"}

    status = {
        "passed": "work_verified",
        "failed": "failed",
        "disputed": "disputed",
    }[frame["verdict"]]
    return {"verified": True, "status": status, "frame": frame}
