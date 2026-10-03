import json
import os
import time
from pathlib import Path
from typing import Any


STATE_FILE = Path("agent_state.json")

# ---------------------------------------------------------------------------
# Bounded state.
#
# A tclk contract record holds the signed transcript needed to fold one deal,
# and that transcript is the bulk of the state file. Deals settle (or their
# offers expire) within minutes, so anything still non-terminal after this
# window is dead weight: at the time of writing, 26,403 contracts held ~81 MB
# while only 28 had ever resolved. Every batch rewrites the whole file, so
# unbounded growth erodes the batching win and eventually wedges ingestion.
#
# ``prune_state`` therefore drops non-terminal contracts past the TTL, folds
# resolved ones down to a tombstone (an idempotency flag, so a duplicate
# terminal frame cannot re-publish), caps survivors, and trims the DID index.
CONTRACT_TTL_S = 6 * 3600
CONTRACT_MAX = 20_000
DID_INDEX_MAX = 20_000

# ---------------------------------------------------------------------------
# State I/O: process cache + batched writes.
#
# Reading/writing the whole state file per message made the agent structurally
# unable to keep up with a live room (measured: ~100 ms load + ~220 ms
# pretty-printed save on a 2 MB state). The cache makes repeated ``load_state``
# calls within a message or batch free, and ``begin_batch``/``end_batch``
# coalesce the many ``save_state`` calls a message makes into one atomic write
# per batch. Outside a batch every ``save_state`` still hits disk immediately,
# so callers and tests keep write-through semantics.
#
# The cache is keyed by the STATE_FILE path, so patching STATE_FILE (tests,
# alternate profiles) transparently starts from a fresh file.
_STATE_CACHE: dict[str, Any] | None = None
_CACHE_PATH: str | None = None
_BATCH_DEPTH = 0


DEFAULT_STATE = {
    "last_lobby_seq": 0,
    "last_room_seq": 0,
    "last_nonce": 0,

    "last_response_at": 0,
    "topic_times": {},

    "recent_message_hashes": [],
    "tclk_contracts": {},
    "tclk_rooms": [],
    "close_call_capture": {
        "trades": {},
        "outcomes": {},
        "offers": {},
        "prices": [],
        "positions": [],
        "rejected": 0,
    },
    "xaud_attestations": {},
    "xaud_ledger": {},
    "evidence_log": {},
    "did_index": {},
    "agent_index": {},

    "stats": {
        "messages_seen": 0,
        "messages_relevant": 0,
        "responses_sent": 0,
        "responses_skipped": 0,
        "signed_posts": 0,
        "messages_skipped": 0,
        "post_errors": 0,
        "contributions_recorded": 0,
        "tclk_candidates_recorded": 0,
        "attestations_verified": 0,
        "claims_duplicates_suppressed": 0,
        "queries_answered": 0,
    },
}


def load_state() -> dict[str, Any]:
    """
    Load persistent agent state.

    If the state file does not exist or is damaged,
    return a fresh state.
    """

    global _STATE_CACHE, _CACHE_PATH

    path = str(STATE_FILE)
    if _STATE_CACHE is not None and _CACHE_PATH == path:
        return _STATE_CACHE

    state = _read_state()
    _STATE_CACHE = state
    _CACHE_PATH = path
    return state


def _read_state() -> dict[str, Any]:
    """Read and migrate state from disk (uncached)."""

    if not STATE_FILE.exists():
        return new_state()

    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)

        state = new_state()

        # Preserve existing values.
        for key, value in data.items():
            state[key] = value
        # Migrate older state files that do not have room cursors.
        if not isinstance(state.get("room_cursors"), dict):
            state["room_cursors"] = {}

        # Preserve the existing lobby cursor.
        if state["last_lobby_seq"] > state["room_cursors"].get("lobby", 0):
            state["room_cursors"]["lobby"] = state["last_lobby_seq"]

        # Make sure nested structures exist.
        if not isinstance(state.get("topic_times"), dict):
            state["topic_times"] = {}

        if not isinstance(state.get("recent_message_hashes"), list):
            state["recent_message_hashes"] = []

        if not isinstance(state.get("tclk_contracts"), dict):
            state["tclk_contracts"] = {}

        if not isinstance(state.get("tclk_rooms"), list):
            state["tclk_rooms"] = []

        if not isinstance(state.get("close_call_capture"), dict):
            state["close_call_capture"] = {}
        close_call_capture = state["close_call_capture"]
        for key, default in {
            "trades": {}, "outcomes": {}, "offers": {},
            "prices": [], "positions": [], "rejected": 0,
        }.items():
            if not isinstance(close_call_capture.get(key), type(default)):
                close_call_capture[key] = default.copy() if isinstance(default, (dict, list)) else default

        if not isinstance(state.get("xaud_attestations"), dict):
            state["xaud_attestations"] = {}

        if not isinstance(state.get("xaud_ledger"), dict):
            state["xaud_ledger"] = {}

        if not isinstance(state.get("evidence_log"), dict):
            state["evidence_log"] = {}

        if not isinstance(state.get("did_index"), dict):
            state["did_index"] = {}

        if not isinstance(state.get("agent_index"), dict):
            state["agent_index"] = {}
        agent_index = state["agent_index"]
        if not isinstance(agent_index.get("profiles"), dict):
            agent_index["profiles"] = {}
        if not isinstance(agent_index.get("query_times"), dict):
            agent_index["query_times"] = {}

        if not isinstance(state.get("stats"), dict):
            state["stats"] = {}

        # Make sure every statistic exists.
        for key, value in DEFAULT_STATE["stats"].items():
            state["stats"].setdefault(key, value)

        return state

    except (json.JSONDecodeError, OSError) as e:
        print(f"[STATE] Could not read state: {e}")
        print("[STATE] Starting with fresh state.")

        return new_state()


def new_state() -> dict[str, Any]:
    """
    Return a completely fresh state.
    """

    return {
        "last_lobby_seq": DEFAULT_STATE["last_lobby_seq"],
        "last_room_seq": DEFAULT_STATE["last_room_seq"],

        # Persistent cursor for every monitored room.
        "room_cursors": {
            "lobby": DEFAULT_STATE["last_lobby_seq"],
        },

        "last_nonce": DEFAULT_STATE["last_nonce"],

        "last_response_at": DEFAULT_STATE["last_response_at"],
        "topic_times": {},

        "recent_message_hashes": [],
        "tclk_contracts": {},
        "tclk_rooms": [],
        "close_call_capture": {
            "trades": {},
            "outcomes": {},
            "offers": {},
            "prices": [],
            "positions": [],
            "rejected": 0,
        },
        "xaud_attestations": {},
        "xaud_ledger": {},
        "evidence_log": {},
        "did_index": {},
        "agent_index": {},

        "stats": DEFAULT_STATE["stats"].copy(),
    }


def save_state(state: dict[str, Any]) -> None:
    """
    Persist state.

    Outside a batch this is an immediate atomic write. Inside a batch
    (``begin_batch``) the write is deferred and the cache is updated, so a
    burst of per-message saves costs one write instead of hundreds.
    """

    global _STATE_CACHE, _CACHE_PATH

    _STATE_CACHE = state
    _CACHE_PATH = str(STATE_FILE)
    if _BATCH_DEPTH > 0:
        return
    _write_state(state)


def _write_state(state: dict[str, Any]) -> None:
    """Atomic, compact write of the whole state."""

    tmp_file = STATE_FILE.with_suffix(".tmp")

    with open(tmp_file, "w") as f:
        # Compact separators, not indent=2: pretty-printing a multi-megabyte
        # state cost ~220 ms per write and was the live-ingestion bottleneck.
        json.dump(state, f, separators=(",", ":"))

    os.replace(tmp_file, STATE_FILE)


def begin_batch() -> None:
    """Start a batch: subsequent ``save_state`` calls defer their write."""

    global _BATCH_DEPTH
    _BATCH_DEPTH += 1


def end_batch() -> None:
    """End a batch, flushing the accumulated state to disk once."""

    global _BATCH_DEPTH
    if _BATCH_DEPTH > 0:
        _BATCH_DEPTH -= 1
    if _BATCH_DEPTH == 0 and _STATE_CACHE is not None:
        _write_state(_STATE_CACHE)


def increment_stat(
    state: dict[str, Any],
    name: str,
    amount: int = 1,
) -> None:
    """
    Increment a persistent statistic.
    """

    stats = state.setdefault("stats", {})

    stats[name] = stats.get(name, 0) + amount


def remember_message(
    state: dict[str, Any],
    message_hash: str,
    limit: int = 200,
) -> None:
    """
    Remember a message hash.

    Only the most recent `limit` hashes are kept.
    """

    hashes = state.setdefault(
        "recent_message_hashes",
        [],
    )

    if message_hash in hashes:
        return

    hashes.append(message_hash)

    if len(hashes) > limit:
        del hashes[:-limit]


def message_was_seen(
    state: dict[str, Any],
    message_hash: str,
) -> bool:
    """
    Check whether this message was recently processed.
    """

    return message_hash in state.get(
        "recent_message_hashes",
        [],
    )


def prune_state(
    state: dict[str, Any],
    now: float | None = None,
) -> dict[str, int]:
    """Drop dead weight so the state file stays bounded.

    - resolved contracts (``candidate_posted``) collapse to a tombstone that
      still suppresses a duplicate settlement, releasing their transcript;
    - non-terminal contracts older than ``CONTRACT_TTL_S`` are evicted, and so
      are records that predate the ``updated_at`` clock (a legacy state file);
    - the survivor count is capped at ``CONTRACT_MAX``, oldest first;
    - ``did_index`` keeps only its newest ``DID_INDEX_MAX`` entries.

    Returns a small count summary for logging. Safe to call repeatedly.
    """

    if now is None:
        now = time.time()
    cutoff = now - CONTRACT_TTL_S

    removed = 0
    collapsed = 0
    contracts = state.get("tclk_contracts")
    if isinstance(contracts, dict):
        for contract_id in list(contracts):
            record = contracts[contract_id]
            if not isinstance(record, dict):
                del contracts[contract_id]
                removed += 1
                continue
            if record.get("candidate_posted"):
                # Collapse to the idempotency tombstone, keeping only a clock.
                if len(record) > 2 or not record.get("updated_at"):
                    contracts[contract_id] = {
                        "candidate_posted": True,
                        "updated_at": record.get("updated_at", now),
                    }
                    collapsed += 1
                continue
            updated = record.get("updated_at")
            if not isinstance(updated, (int, float)) or updated < cutoff:
                del contracts[contract_id]
                removed += 1

        # Hard cap: evict the oldest survivors, never a tombstone.
        if len(contracts) > CONTRACT_MAX:
            survivors = sorted(
                (
                    (contract_id, record.get("updated_at", 0))
                    for contract_id, record in contracts.items()
                    if isinstance(record, dict) and not record.get("candidate_posted")
                ),
                key=lambda item: item[1],
            )
            for contract_id, _ in survivors[: len(contracts) - CONTRACT_MAX]:
                del contracts[contract_id]
                removed += 1

    did_removed = 0
    did_index = state.get("did_index")
    if isinstance(did_index, dict) and len(did_index) > DID_INDEX_MAX:
        for key in list(did_index)[: len(did_index) - DID_INDEX_MAX]:
            del did_index[key]
            did_removed += 1

    return {
        "contracts_removed": removed,
        "contracts_collapsed": collapsed,
        "contracts_kept": len(contracts) if isinstance(contracts, dict) else 0,
        "did_index_removed": did_removed,
    }


def get_next_nonce(
    state: dict[str, Any],
) -> int:
    """
    Generate a monotonically increasing millisecond nonce.
    """

    nonce = int(time.time() * 1000)

    last_nonce = state.get(
        "last_nonce",
        0,
    )

    if nonce <= last_nonce:
        nonce = last_nonce + 1

    state["last_nonce"] = nonce

    return nonce
