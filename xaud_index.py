"""XAUD agent index: per-agent profiles over verifiable, observed work.

XAUD's mission is an index of *good* agents: who has actually completed
paid work, passed attestations, or produced anchored claims — not who talks
the most. This module keeps that index as pure functions over the agent
state dict (no I/O), so it stays testable and drops into agent.py.

What is counted, and why it is honest:

- ``observe_signed``  — base layer. Every transport-verified message from a
  full DID updates activity stats (rooms, first/last seen) and feeds template
  dedupe. This is observation, never judgement.
- ``record_claim``    — an anchored, transport-verified work claim XAUD is
  about to publish. Exact/near-duplicate templates collapse into counters
  instead of new room records, so a 12x "mirror note published" spammer
  yields one observation, not twelve.
- ``on_settlement``   — a fully folded, transcript-verified tclk lifecycle
  (payer paid / payee was paid). The strongest signal in the index.
- ``on_attestation``  — an evaluator-signed work attestation verdict.
- ``on_tclk``         — observed lifecycle roles (offers posted, accepts,
  locks, reveals). A reveal is the payee proving the secret: the closest
  live proxy for "completed the job", short of a full fold.

Queries rank by verified work first, claims second. Reputation is earned
through verifiable activity, never declared through self-description.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

# A profile only keeps its most recent evidence references.
EVIDENCE_REFS_PER_AGENT = 20
# Per-agent near-duplicate template memory.
TEMPLATES_PER_AGENT = 40
# An agent whose identical template repeats this many times is flagged.
REPEAT_FLAG_AT = 5
# Suppress re-publishing a claim template seen within this window.
CLAIM_DUP_WINDOW_S = 7 * 24 * 3600
# Cooldown between XAUD answers to the same query in the same room.
QUERY_COOLDOWN_S = 30
# Keep the whole index bounded; drop the least recently seen agents.
MAX_PROFILES = 2500
# Query replies are capped at this many candidates.
QUERY_LIMIT = 6
MAX_QUERY_LIMIT = 20

# Capability vocabulary: bounded keyword tags mined from verified work
# contexts (a folded settlement's tclk job context, an anchored claim's
# summary). This lets queries match the words real work is described with
# ("census", "review", "blockrewards"), not just the fixed task categories.
CAPABILITY_TAGS_PER_TEXT = 6
MAX_CAPABILITY_TAGS_PER_AGENT = 48
CAPABILITY_TAG_PREFIX = "cap:"

DID_BODY = re.compile(r"^did:key:(z6Mk[1-9A-HJ-NP-Za-km-z]{44})$")

# Normalization for near-duplicate detection: drop URL payloads, hex-looking
# tokens, bare numbers and punctuation, so "proof: 9db89ff0" and
# "proof: 9ffbf82b" collapse to the same template.
_URL_RE = re.compile(r"https?://\S+")
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_HEXLIKE_RE = re.compile(r"\b[0-9a-f]{8,}\b")
_NUM_RE = re.compile(r"\b[0-9]+\b")
_JUNK_RE = re.compile(r"[^a-z0-9 ]+")

# Capability mining: token characters, a floor on token length (with a small
# allowlist of real short capabilities), and words that are protocol/registry
# boilerplate rather than a capability.
_CAP_TOKEN_RE = re.compile(r"[a-z0-9+#]+")
_CAP_MIN_LEN = 3
_CAP_SHORT_ALLOW = frozenset(
    {"ai", "ml", "qa", "ui", "ux", "vm", "kv", "db", "os", "3d", "xr", "vr", "ar"}
)
_CAP_STOPWORDS = frozenset(
    {
        "the", "and", "for", "with", "that", "this", "from", "your", "you",
        "are", "was", "were", "has", "have", "had", "will", "would", "can",
        "could", "should", "not", "but", "any", "all", "our", "out", "who",
        "how", "what", "when", "where", "which", "why", "into", "onto",
        "over", "under", "about", "after", "before", "than", "then", "them",
        "they", "their", "there", "here", "its", "per", "via", "some",
        "anyone", "someone", "many", "more", "most", "new", "one", "two",
        "get", "got", "give", "made", "make", "also", "need", "want",
        "looking", "find", "search", "please", "reply", "post", "posted",
        "using", "use", "used", "job", "task", "work", "agent", "xaud",
        "verified", "verify", "verification", "settlement", "settled",
        "payment", "paid", "pay", "payee", "payer", "tclk", "proto", "room",
        "seq", "note", "summary", "report", "record", "tx", "hash", "value",
        "exact", "offer",
    }
)


def _stem(token: str) -> str:
    """Light singularization that leaves words like 'census'/'analysis' alone."""
    if token.endswith(("ss", "us", "is")):
        return token
    if token.endswith("s") and len(token) > 3:
        return token[:-1]
    return token


def capability_tags(
    text: str,
    limit: int = CAPABILITY_TAGS_PER_TEXT,
) -> list[str]:
    """Extract bounded, deduped capability keywords from verified work text.

    Deterministic and order-preserving: the first distinct qualifying tokens
    win, so a job context like ``census | how many offers…`` yields ``census``
    rather than protocol boilerplate.
    """
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for raw in _CAP_TOKEN_RE.findall(str(text).lower()):
        if raw.isdigit():
            continue
        if len(raw) < _CAP_MIN_LEN and raw not in _CAP_SHORT_ALLOW:
            continue
        token = _stem(raw)
        if token in _CAP_STOPWORDS or token in seen:
            continue
        seen.add(token)
        found.append(token)
        if len(found) >= limit:
            break
    return found


def _prune_capabilities(profile: dict[str, Any]) -> None:
    """Keep the per-agent capability vocabulary bounded and deterministic."""
    tags = profile.get("tags") or {}
    caps = [key for key in tags if key.startswith(CAPABILITY_TAG_PREFIX)]
    if len(caps) <= MAX_CAPABILITY_TAGS_PER_AGENT:
        return
    caps.sort(key=lambda key: (tags[key], key))
    for key in caps[: len(caps) - MAX_CAPABILITY_TAGS_PER_AGENT]:
        del tags[key]


def _note_capabilities(profile: dict[str, Any], text: str | None) -> None:
    """Mine verified work text into bounded ``cap:`` capability tags."""
    if not text:
        return
    for token in capability_tags(text):
        _bump(profile, "tags", CAPABILITY_TAG_PREFIX + token)
    _prune_capabilities(profile)


def abbreviate(did: str) -> str:
    """Server-identical short form ``z6Mk…xxxx`` for a full did:key."""
    body = DID_BODY.match(did or "")
    if body is None:
        return did
    raw = body.group(1)
    return f"{raw[:4]}…{raw[-4:]}"


def template_hash(text: str, normalize_numbers: bool) -> str:
    """Deterministic near-duplicate fingerprint of a message template."""
    lowered = (text or "").lower()
    lowered = _URL_RE.sub(" url ", lowered)
    lowered = _HEX_RE.sub(" hex ", lowered)
    if normalize_numbers:
        lowered = _HEXLIKE_RE.sub(" hex ", lowered)
        lowered = _NUM_RE.sub(" n ", lowered)
    lowered = _JUNK_RE.sub(" ", lowered)
    lowered = re.sub(r"\s+", " ", lowered).strip()
    return hashlib.sha256(lowered.encode()).hexdigest()[:16]


def _ensure_index(state: dict[str, Any]) -> dict[str, Any]:
    index = state.setdefault("agent_index", {})
    index.setdefault("profiles", {})
    index.setdefault("query_times", {})
    return index


def _profile(state: dict[str, Any], did: str, now: int | None = None) -> dict[str, Any]:
    """Return the profile for a full did:key, pruning the index when full."""
    index = _ensure_index(state)
    profiles = index["profiles"]
    profile = profiles.get(did)
    if profile is None:
        if len(profiles) >= MAX_PROFILES:
            oldest = min(
                profiles,
                key=lambda d: profiles[d].get("last_seen", 0),
            )
            del profiles[oldest]
        first = now if now is not None else int(time.time())
        profile = {
            "did": did,
            "abbrev": abbreviate(did),
            "first_seen": first,
            "last_seen": first,
            "rooms": {},
            "activity_types": {},
            "tags": {},
            "claims_published": 0,
            "claims_duplicates": 0,
            "attestations": {"passed": 0, "failed": 0, "disputed": 0},
            "settlements": {
                "received": 0,
                "paid": 0,
                "amount_received": {},
                "amount_paid": {},
            },
            "tclk": {
                "offers_posted": 0,
                "accepts": 0,
                "locks": 0,
                "reveals": 0,
                "refunds": 0,
            },
            "evidence_refs": [],
            "templates": {},
            "flags": [],
        }
        profiles[did] = profile
    return profile


def _bump(profile: dict[str, Any], bucket: str, key: str, amount: int = 1) -> None:
    counter = profile.setdefault(bucket, {})
    counter[key] = counter.get(key, 0) + amount


def _note_evidence(profile: dict[str, Any], room: str, seq: int) -> None:
    refs = profile.setdefault("evidence_refs", [])
    ref = f"{room}:{seq}"
    if ref in refs:
        refs.remove(ref)
    refs.append(ref)
    del refs[:-EVIDENCE_REFS_PER_AGENT]


def _template_entry(
    profile: dict[str, Any],
    text: str,
    room: str,
    seq: int,
    now: int,
) -> tuple[dict[str, Any], int]:
    """Return (entry, repeat_count) for this text's near fingerprint.

    Template memory is bounded per agent; the newest fingerprint always
    displaces the oldest when full."""
    templates = profile.setdefault("templates", {})
    near = template_hash(text, normalize_numbers=True)
    entry = templates.get(near)
    if entry is None:
        if len(templates) >= TEMPLATES_PER_AGENT:
            del templates[next(iter(templates))]
        entry = {"count": 0, "last_ts": 0, "last_room": room, "last_seq": seq}
        templates[near] = entry
    entry["count"] += 1
    entry["last_ts"] = now
    entry["last_room"] = room
    entry["last_seq"] = seq
    return entry, entry["count"]


def observe_signed(
    state: dict[str, Any],
    did: str,
    room: str,
    seq: int,
    text: str,
    now: int | None = None,
    low_value: bool = False,
) -> int:
    """Base observation of a transport-verified signed message.

    Updates activity stats and template memory. Returns the template repeat
    count (1 = first time this sender posted this template).
    """
    profile = _profile(state, did, now)
    now = int(now if now is not None else time.time())
    profile["last_seen"] = now
    _bump(profile, "rooms", room)
    _, repeat = _template_entry(profile, text, room, seq, now)
    if (
        low_value
        and repeat >= REPEAT_FLAG_AT
        and "repeater" not in profile["flags"]
    ):
        profile["flags"].append("repeater")
    return repeat


def record_claim(
    state: dict[str, Any],
    did: str,
    room: str,
    seq: int,
    text: str,
    tags: list[str] | None = None,
    activity_type: str | None = None,
    task: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Register an anchored work claim before it is published.

    Returns ``{"action": "publish"}`` for a genuinely new claim and
    ``{"action": "duplicate", "repeat": n}`` when this agent has already
    claimed this template within CLAIM_DUP_WINDOW_S — the caller then skips
    the room write and only the counters move.
    """
    profile = _profile(state, did, now)
    now = int(now if now is not None else time.time())
    entry, repeat = _template_entry(profile, text, room, seq, now)
    previous_ts = entry.get("_prev_ts", 0)
    if repeat > 1 and now - previous_ts < CLAIM_DUP_WINDOW_S:
        profile["claims_duplicates"] += 1
        return {"action": "duplicate", "repeat": repeat}
    entry["_prev_ts"] = now

    profile["claims_published"] += 1
    if tags:
        for tag in tags:
            _bump(profile, "tags", str(tag).lower())
    if activity_type:
        _bump(profile, "activity_types", activity_type)
    if task:
        _bump(profile, "tags", task)
    # The claim's own words are its capability vocabulary; they are bounded
    # and stopword-filtered so generic verification prose does not pollute it.
    _note_capabilities(profile, text)
    _note_evidence(profile, room, seq)
    return {"action": "publish", "repeat": repeat}


def on_settlement(
    state: dict[str, Any],
    payer: str,
    payee: str,
    amount: str,
    asset: str,
    outcome: str,
    job_proto: str | None = None,
    job_context: str | None = None,
    rail: str | None = None,
    now: int | None = None,
) -> None:
    """Credit both sides of a transcript-verified settlement.

    ``job_context`` is the folded offer's job context text. It is the payee's
    (worker's) capability vocabulary, so only the payee profile is mined with
    it; the payer is hiring demand, not capability.
    """
    now = int(now if now is not None else time.time())
    index = _ensure_index(state)
    outcomes = index.setdefault("settlement_outcomes", {})
    outcome_key = f"{rail or 'unknown'}:{outcome}"
    outcomes[outcome_key] = outcomes.get(outcome_key, 0) + 1
    if outcome == "claimed":
        payer_profile = _profile(state, payer, now)
        payee_profile = _profile(state, payee, now)
        payer_profile["settlements"]["paid"] += 1
        payee_profile["settlements"]["received"] += 1
        _add_amount(payer_profile["settlements"]["amount_paid"], amount, asset)
        _add_amount(payee_profile["settlements"]["amount_received"], amount, asset)
        if job_proto:
            _bump(payee_profile, "tags", f"proto:{job_proto}")
        # Every verified settlement is a tclk lifecycle; both sides worked
        # through the protocol, the payee by completing the job.
        _bump(payee_profile, "tags", "tclk")
        _bump(payer_profile, "tags", "tclk")
        _note_capabilities(payee_profile, job_context)
        for profile in (payer_profile, payee_profile):
            profile["last_seen"] = now


def _add_amount(bucket: dict[str, Any], amount: str, asset: str) -> None:
    try:
        value = int(amount)
    except (TypeError, ValueError):
        return
    bucket[asset] = bucket.get(asset, 0) + value


def on_attestation(
    state: dict[str, Any],
    worker: str,
    status: str,
    task_type: str | None = None,
    now: int | None = None,
) -> None:
    """Register an evaluator-signed attestation verdict about a worker."""
    profile = _profile(state, worker, now)
    now = int(now if now is not None else time.time())
    bucket = profile.setdefault("attestations", {})
    bucket[status] = bucket.get(status, 0) + 1
    if status == "passed" and task_type:
        _bump(profile, "tags", task_type)
    profile["last_seen"] = now


def on_tclk(
    state: dict[str, Any],
    did: str,
    kind: str,
    room: str,
    seq: int,
    proto: str | None = None,
    now: int | None = None,
) -> None:
    """Register an observed tclk lifecycle role for a full DID."""
    profile = _profile(state, did, now)
    now = int(now if now is not None else time.time())
    counter = profile.setdefault("tclk", {})
    key = {
        "offer": "offers_posted",
        "accept": "accepts",
        "lock": "locks",
        "reveal": "reveals",
        "refund": "refunds",
    }.get(kind)
    if key is None:
        return
    counter[key] = counter.get(key, 0) + 1
    # Payee-side activity is the work signal; payer-side offers are hiring
    # demand. Only payee-side roles feed capability tags.
    if key in ("accepts", "reveals") and proto:
        _bump(profile, "tags", f"proto:{proto}")
        _bump(profile, "tags", "tclk")
    _note_evidence(profile, room, seq)
    profile["last_seen"] = now


def query(
    state: dict[str, Any],
    text: str,
    limit: int = QUERY_LIMIT,
    min_score: int = 0,
    since: int | None = None,
    now: int | None = None,
) -> list[dict[str, Any]]:
    """Rank observed agents against free-text capability terms.

    Verified work dominates: transcript settlements first, attestations next,
    then anchored claims and reveals. An agent with zero work signals is never
    returned, no matter how chatty it is.
    """
    profiles = _ensure_index(state)["profiles"]
    limit = max(1, min(int(limit), MAX_QUERY_LIMIT))
    min_score = max(0, int(min_score))
    now = int(now if now is not None else time.time())
    stopwords = {
        "a", "an", "me", "my", "for", "to", "the", "in", "on", "of",
        "with", "and", "or", "do", "can", "you", "any", "who", "that",
        "this", "agent", "xaud", "find", "search", "recommend", "show",
        "list", "top", "give", "need", "want", "some", "someone", "is",
        "are", "been", "has", "have", "done", "does", "work", "good",
        "trusted", "reliable", "verified", "best", "help", "please",
    }
    # Natural-language capability words -> the vocabulary profiles actually
    # carry (task categories, activity types, proto names).
    aliases = {
        "trade": "trading", "trader": "trading", "trading": "trading",
        "build": "builder", "builds": "builder", "coder": "builder",
        "developer": "builder", "developers": "builder",
        "validator": "network", "validators": "network",
        "auditor": "audit", "auditors": "audit",
        "researcher": "research", "researchers": "research",
        "writer": "publication", "writers": "publication",
        "settle": "settlement", "settles": "settlement",
        "attester": "identity", "verifier": "identity",
    }
    tokens = set()
    for raw in re.sub(r"[^a-z0-9+#]", " ", (text or "").lower()).split():
        token = _stem(raw)
        token = aliases.get(token, token)
        if len(token) > 1 and token not in stopwords:
            tokens.add(token)
    candidates: list[dict[str, Any]] = []
    for did, profile in profiles.items():
        score = 0
        reasons: list[str] = []
        if profile["settlements"]["received"] > 0:
            score += 30 + profile["settlements"]["received"] * 3
            reasons.append(f"{profile['settlements']['received']} paid job(s)")
        if profile["settlements"]["paid"] > 0:
            score += 1
            reasons.append("hirer")
        passed = profile["attestations"].get("passed", 0)
        if passed:
            score += 20 + passed * 2
            reasons.append(f"{passed} attestation(s) passed")
        reveals = profile["tclk"].get("reveals", 0)
        if reveals:
            score += reveals * 4
            reasons.append(f"{reveals} reveal(s)")
        if profile["claims_published"] > 0:
            score += min(profile["claims_published"], 5)
            reasons.append(f"{profile['claims_published']} claim(s)")
        if score == 0:
            continue
        if since is not None and profile["last_seen"] < since:
            continue
        if "repeater" in profile["flags"]:
            score -= 15
            reasons.append("repeat-poster")
        if tokens:
            tags = set(profile["tags"]) | set(profile["activity_types"])
            parts = set()
            for tag in tags:
                parts.add(tag)
                parts.update(part for part in tag.split(":") if part)
            matches = parts & tokens
            if not matches:
                continue
            score += len(matches) * 2
        if score < min_score:
            continue
        claimed = profile["settlements"].get("received", 0)
        passed = profile["attestations"].get("passed", 0)
        candidates.append(
            {
                "did": did,
                "abbrev": profile["abbrev"],
                "score": score,
                "reasons": reasons,
                "last_seen": profile["last_seen"],
                "age_s": max(0, now - profile["last_seen"]),
                "signals": {
                    "claimed_jobs": claimed,
                    "attestations_passed": passed,
                    "attestations_failed": profile["attestations"].get("failed", 0),
                    "claims": profile["claims_published"],
                    "reveals": profile["tclk"].get("reveals", 0),
                },
                "tags": sorted(
                    key.removeprefix(CAPABILITY_TAG_PREFIX)
                    for key in profile.get("tags", {})
                    if key.startswith(CAPABILITY_TAG_PREFIX)
                )[:12],
                "evidence_refs": profile.get("evidence_refs", [])[-5:],
            }
        )
    candidates.sort(key=lambda item: (-item["score"], -item["last_seen"]))
    return candidates[:limit]


def format_candidate(candidate: dict[str, Any], rank: int) -> str:
    """One compact, machine-parsable line for a query answer.

    Names the full DID: an abbreviated ``z6Mk…xxxx`` cannot be hired or
    looked up, so a discovery answer that only abbreviates is not actionable.
    """
    reasons = ", ".join(candidate["reasons"])
    age = candidate.get("age_s", 0)
    signals = candidate.get("signals", {})
    return (
        f"{rank}. {candidate['did']} | score {candidate['score']} | "
        f"age {age}s | claimed {signals.get('claimed_jobs', 0)} | "
        f"attested {signals.get('attestations_passed', 0)} | {reasons}"
    )


def index_summary(state: dict[str, Any]) -> dict[str, Any]:
    """Aggregate stats for a ``xaud status`` answer."""
    profiles = _ensure_index(state)["profiles"]
    summary = {
        "agents_tracked": len(profiles),
        "agents_with_paid_work": 0,
        "agents_with_attestations": 0,
        "agents_with_claims": 0,
        "agents_flagged_repeaters": 0,
        "last_index_update": 0,
        "evidence_refs": 0,
        "claimed_jobs": 0,
        "settlement_outcomes": dict(
            _ensure_index(state).get("settlement_outcomes", {})
        ),
    }
    for profile in profiles.values():
        summary["last_index_update"] = max(
            summary["last_index_update"], profile.get("last_seen", 0)
        )
        summary["evidence_refs"] += len(profile.get("evidence_refs", []))
        summary["claimed_jobs"] += profile["settlements"].get("received", 0)
        if profile["settlements"]["received"] > 0:
            summary["agents_with_paid_work"] += 1
        if profile["attestations"].get("passed", 0) > 0:
            summary["agents_with_attestations"] += 1
        if profile["claims_published"] > 0:
            summary["agents_with_claims"] += 1
        if "repeater" in profile["flags"]:
            summary["agents_flagged_repeaters"] += 1
    return summary


def query_allowed(state: dict[str, Any], room: str, text: str, now: int) -> bool:
    """Cooldown gate so XAUD never answers the same ask twice in a row."""
    index = _ensure_index(state)
    key = f"{room}|{template_hash(text, normalize_numbers=True)}"
    previous = index["query_times"].get(key, 0)
    if now - previous < QUERY_COOLDOWN_S:
        return False
    index["query_times"][key] = now
    if len(index["query_times"]) > 500:
        # Drop the stale half of the cooldown table.
        cutoff = now - QUERY_COOLDOWN_S * 2
        index["query_times"] = {
            k: v for k, v in index["query_times"].items() if v > cutoff
        }
    return True
