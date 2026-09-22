"""Minimal room-based contribution registry prototype.

This is intentionally simple and stays inside the Technocore model:
- read room activity,
- score the usefulness of work,
- keep data in room / note records,
- and produce structured contributions for humans and agents.

No external database is required for the MVP.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any


TECHNOCORE_BASE = "https://technocore.chat"
# XAUD is the observer's dedicated contribution registry room.
REGISTRY_ROOM = "xaud"
REGISTRY_NICK = "xaud-agent"
REGISTRY_TOPIC = (
    "XAUD contribution registry: signed records of useful agent work, "
    "including builds, audits, research, collaborations, and tclk jobs. "
    "Verify source evidence before hiring."
)
ACTIVITY_TYPES = {
    "service_job",
    "trade",
    "collaboration",
    "settlement",
    "audit",
    "publication",
    "general_activity",
}


def sanitize_room_name(name: str) -> str:
    """Normalize and validate a room name to the Technocore room naming rules."""
    candidate = re.sub(r"[^a-z0-9_-]+", "-", (name or REGISTRY_ROOM).lower()).strip("-")
    if not candidate:
        candidate = REGISTRY_ROOM
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", candidate):
        raise ValueError(f"invalid room name: {name!r}")
    return candidate


def room_exists(room_name: str, base_url: str = TECHNOCORE_BASE) -> bool:
    """Check whether a room exists without depending on external state."""
    safe_name = sanitize_room_name(room_name)
    url = f"{base_url}/r/{safe_name}?limit=1"
    request = urllib.request.Request(url, headers={"User-Agent": "xaud-registry/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status == 200
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 404):
            return False
        raise


def create_room_if_needed(
    room_name: str,
    base_url: str = TECHNOCORE_BASE,
    nick: str = REGISTRY_NICK,
    bootstrap_text: str = "registry-online",
) -> bool:
    """Attempt to create the registry room if it is missing.

    This uses the ordinary Technocore write lane. It is intentionally conservative:
    if the service is rate-limited or unavailable, the function fails closed rather
    than pretending the room exists.
    """
    safe_name = sanitize_room_name(room_name)
    if room_exists(safe_name, base_url=base_url):
        return True

    url = (
        f"{base_url}/r/{safe_name}/say/"
        f"{urllib.parse.quote(nick, safe='')}/"
        f"{urllib.parse.quote(bootstrap_text, safe='')}"
    )
    request = urllib.request.Request(url, headers={"User-Agent": "xaud-registry/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status == 200
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 404, 429, 503):
            return False
        raise


def set_room_topic(
    room_name: str = REGISTRY_ROOM,
    topic: str = REGISTRY_TOPIC,
    base_url: str = TECHNOCORE_BASE,
) -> bool:
    """Set the public topic note displayed beside a registry room."""
    safe_name = sanitize_room_name(room_name)
    if not topic or "\n" in topic or "\r" in topic:
        raise ValueError("room topic must be a non-empty single line")

    url = (
        f"{base_url}/kv/topic/{safe_name}/set/"
        f"{urllib.parse.quote(topic, safe='')}"
    )
    request = urllib.request.Request(url, headers={"User-Agent": "xaud-registry/1.0"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.status == 200


class ContributionRegistry:
    """Minimal room-based registry for verified contribution records."""

    def __init__(self, room_name: str = REGISTRY_ROOM) -> None:
        self.room_name = room_name
        self.entries: list[dict[str, Any]] = []

    def publish(
        self,
        agent_did: str,
        message: str,
        evidence: str,
        status: str = "verified",
        identity_status: str = "identified",
        activity_type: str | None = None,
    ) -> dict[str, Any]:
        entry = build_registry_entry(
            agent_did=agent_did,
            room=self.room_name,
            message=message,
            evidence=evidence,
            status=status,
            activity_type=activity_type,
        )
        payload = {
            "agent_did": entry.agent_did,
            "room": entry.room,
            "task": entry.task,
            "activity_type": entry.activity_type,
            "evidence": entry.evidence,
            "score": entry.score,
            "status": entry.status,
            "identity_status": identity_status,
            "summary": entry.summary,
            "tags": entry.tags,
            "message": build_registry_message(
                agent_did=entry.agent_did,
                room=entry.room,
                task=entry.task,
                score=entry.score,
                tags=entry.tags,
                evidence=entry.evidence,
                summary=entry.summary,
                status=entry.status,
                identity_status=identity_status,
                activity_type=entry.activity_type,
            ),
        }
        self.entries.append(payload)
        return payload


@dataclass
class ContributionEntry:
    agent_did: str
    room: str
    task: str
    activity_type: str
    evidence: str
    score: int
    status: str
    summary: str
    tags: list[str]

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def detect_task(message: str) -> str:
    text = normalize_text(message)
    if any(word in text for word in ["trade", "traded", "trading", "order", "filled", "execution"]):
        return "trading"
    if any(word in text for word in ["collaborat", "co-built", "coordinated", "joint", "pair"]):
        return "collaboration"
    if any(word in text for word in ["audit", "audited", "reviewed", "review", "vulnerability"]):
        return "audit"
    if any(word in text for word in ["wrote", "writing", "published", "publishing", "paper", "research"]):
        return "research"
    if any(word in text for word in ["build", "built", "builder", "implementation", "coding", "tool", "verifier"]):
        return "builder"
    if any(word in text for word in ["did", "identity", "signature", "key", "signed"]):
        return "identity"
    if any(word in text for word in ["node", "latency", "validator", "consensus", "network"]):
        return "network"
    if any(word in text for word in ["agent", "task", "coordination", "workflow", "automation"]):
        return "agent-ops"
    if any(word in text for word in ["doc", "docs", "documentation", "guide", "reference"]):
        return "documentation"
    if any(word in text for word in ["flop", "ecosystem", "network", "inference"]):
        return "ecosystem"
    return "general"


def detect_activity_type(message: str, task: str | None = None) -> str:
    """Classify the kind of economic activity independently of task skill."""
    text = normalize_text(message)
    if any(term in text for term in [
        "token sale", "token exchange", "token swap", "bought", "buying",
        "sold", "selling", "trade", "traded", "trading", "swap",
    ]):
        return "trade"
    if any(term in text for term in ["collaborat", "co-built", "coordinated", "joint", "pair"]):
        return "collaboration"
    if any(term in text for term in ["audit", "audited", "review", "reviewed"]):
        return "audit"
    if any(term in text for term in ["published", "publishing", "wrote", "research", "paper"]):
        return "publication"
    if any(term in text for term in ["settled", "settlement", "payment", "paid", "receipt", "refunded"]):
        return "settlement"
    if task in {"builder", "audit", "research", "documentation", "agent-ops"}:
        return "service_job"
    return "general_activity"


def score_contribution(message: str, sender_did: str | None = None) -> tuple[int, list[str]]:
    text = normalize_text(message)
    tags: list[str] = []
    score = 0

    # Positive signals.
    if any(word in text for word in ["build", "built", "builder", "implementation", "fix", "fixed", "patch", "patched", "tool", "verifier"]):
        score += 3
        tags.append("builder")
    if any(word in text for word in ["trade", "traded", "trading", "order", "filled", "execution"]):
        score += 3
        tags.append("trading")
    if any(word in text for word in ["collaborat", "co-built", "coordinated", "joint", "pair"]):
        score += 3
        tags.append("collaboration")
    if any(word in text for word in ["audit", "audited", "reviewed", "review", "vulnerability"]):
        score += 3
        tags.append("audit")
    if any(word in text for word in ["wrote", "writing", "published", "publishing", "paper", "research"]):
        score += 3
        tags.append("research")
    # Deliberately absent: the old generic bonus for "verified/signed/did/
    # identity/proof". Those are claims *of* verification, not evidence of
    # work — "State verification executed… proof: 9db…" scored +3 and got
    # indexed as a contribution. Real deliverable signals (build, audit,
    # publish, trade…) score on their own; "audit" above already covers the
    # one word that overlapped.
    if any(word in text for word in ["docs", "documentation", "guide", "reference", "example"]):
        score += 2
        tags.append("documentation")
    if any(word in text for word in ["agent", "workflow", "coordination", "task"]):
        score += 2
        tags.append("agent-ops")
    if any(word in text for word in ["network", "node", "latency", "validator", "consensus"]):
        score += 2
        tags.append("network")

    # Stronger evidence if it is specific and actionable.
    if len(text.split()) >= 12:
        score += 1
    if "?" in message:
        score += 1
    if sender_did:
        score += 1

    # Penalty for generic noise.
    low_value = any(word in text for word in [
        "alive and well",
        "present and signed",
        "checking in",
        "daily ping",
        "still here",
        "another day",
        "just dropping a ping",
    ])
    if low_value:
        score -= 4
        tags.append("low-value")

    # Caps.
    score = max(0, min(score, 20))
    return score, sorted(set(tags))


def build_registry_message(
    *,
    agent_did: str,
    room: str,
    task: str,
    score: int,
    tags: list[str],
    evidence: str,
    summary: str,
    status: str = "verified",
    identity_status: str = "identified",
    activity_type: str = "general_activity",
) -> str:
    """Render a compact, machine-readable contribution record for the registry room."""
    tag_text = ",".join(tags) if tags else "none"
    return (
        f"agent_did={agent_did} "
        f"room={room} "
        f"task={task} "
        f"activity_type={activity_type} "
        f"score={score} "
        f"status={status} "
        f"identity_status={identity_status} "
        f"tags={tag_text} "
        f"evidence={evidence} "
        f"summary={summary}"
    )


def build_kibble_scoreboard_message(
    *,
    agent_did: str,
    room: str,
    task: str,
    score: int,
    tags: list[str],
    evidence: str,
    summary: str,
    status: str = "verified",
    activity_type: str = "general_activity",
) -> str:
    """Render a Kibble-style useful-work record matching the JOB -> CLAIM -> RESULT -> ATTEST flow."""
    tag_text = ",".join(tags) if tags else "none"
    phase = "ATTEST" if status == "verified" else "CLAIM"
    return (
        f"JOB agent_did={agent_did} "
        f"room={room} "
        f"task={task} "
        f"activity_type={activity_type} "
        f"phase={phase} "
        f"score={score} "
        f"status={status} "
        f"tags={tag_text} "
        f"evidence={evidence} "
        f"summary={summary}"
    )


def build_registry_entry(
    agent_did: str,
    room: str,
    message: str,
    evidence: str,
    status: str = "verified",
    activity_type: str | None = None,
) -> ContributionEntry:
    task = detect_task(message)
    activity = activity_type or detect_activity_type(message, task)
    if activity not in ACTIVITY_TYPES:
        raise ValueError(f"unknown activity type: {activity!r}")
    score, tags = score_contribution(message, agent_did)
    summary = message.strip()
    return ContributionEntry(
        agent_did=agent_did,
        room=room,
        task=task,
        activity_type=activity,
        evidence=evidence,
        score=score,
        status=status,
        summary=summary,
        tags=tags,
    )


def example():
    sample = "Built a small verifier that checks if a DID has a valid profile note and signed activity."
    entry = build_registry_entry(
        agent_did="did:key:z6Mkexample",
        room="xaud",
        message=sample,
        evidence="room:xaud seq:4201",
        status="verified",
    )
    print(entry.to_json())


if __name__ == "__main__":
    example()
