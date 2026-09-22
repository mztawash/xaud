import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path

from contribution_registry import build_registry_entry
from tclk_observer import (
    DID_PATTERN,
    TclkFrameError,
    deal_room,
    fold_tclk_transcript,
    fold_tclk_lifecycle,
    order_tclk_records,
    parse_tclk_frame,
    verify_transport_record,
)
from xaud_attestation import verify_attestation_record
from xaud_index import (
    index_summary,
    on_attestation,
    on_settlement,
    on_tclk,
    query as index_query,
    query_allowed,
    record_claim as index_record_claim,
    format_candidate,
    observe_signed,
)
from xaud_records import (
    XaudRecordError,
    build_observation_frame,
    build_settlement_frame,
    parse_xaud_record,
)
from state import (
    load_state,
    save_state,
    increment_stat,
    remember_message,
    message_was_seen,
    get_next_nonce,
    begin_batch,
    end_batch,
    prune_state,
)


# ============================================================
# CONFIG
# ============================================================

BASE = "https://technocore.chat"
LOBBY = "lobby"

# ============================================================
# ACTIVE ROOMS
# ============================================================

ACTIVE_ROOMS = [
    "lobby",
    "technocore",
    "inference-agents",
    "ai",
    "agent-security",
    "validators",
    "crypto",
    "flop-network",
    "flop-collective",
    "technocore-api",
    "infra",
    "tclk-offers",
    "xaud",
]

# The rooms the agent always watches. Deal rooms are derived at runtime and
# appended; ``rebuild_active_rooms`` restores this base plus whatever contracts
# remain after pruning.
BASE_ROOMS = tuple(ACTIVE_ROOMS)

USER_AGENT = "xaud-agent/4.0"

EXPECTED_DID = (
    "did:key:z6Mkg59iL4k3hPUAGFKzEM9EQRxFLtn5W18q2XcuiVPz4mBQ"
)


def load_env_file(path: str = ".env") -> None:
    """Load KEY=VALUE pairs into the process environment if not already set.

    Tolerates the two common file styles (plain ``SIGN_SEED=...`` and shell
    ``export SIGN_SEED=...``) so the agent boots from any shell, cron job or
    service manager — not just from a terminal where the user happened to
    source .env. Existing environment values win.
    """
    env_path = Path(path)
    if not env_path.exists():
        return
    for raw_line in env_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("\"", "'"):
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def is_own_sender(sender):
    """Return True for the agent's DID in either full or abbreviated room form."""
    if not sender:
        return False

    value = str(sender).strip()

    if value == EXPECTED_DID:
        return True

    if value.startswith("did:key:"):
        value = value.split("did:key:", 1)[1]

    expected_base = EXPECTED_DID.split("did:key:", 1)[1]

    if value == expected_base:
        return True

    if value.startswith("z6Mk") and expected_base.startswith("z6Mk"):
        value_tail = value[-6:]
        expected_tail = expected_base[-6:]
        value_head = value[:12]
        expected_head = expected_base[:12]

        if value_head == expected_head and value_tail == expected_tail:
            return True

    if "z6Mk" in value and "4mBQ" in value:
        return True

    return False

# Minimum score required before considering a reply.
MIN_RELEVANCE = 3

# Same-message protection.
MESSAGE_HASH_LIMIT = 500


# ============================================================
# TOPICS
# ============================================================

TOPICS = {
    "trading": [
        "trading",
        "trade",
        "trader",
        "market",
        "markets",
        "liquidity",
        "volume",
        "execution",
        "orderbook",
        "order book",
        "price",
        "slippage",
    ],

    "tokenomics": [
        "tokenomics",
        "token supply",
        "supply",
        "emission",
        "emissions",
        "vesting",
        "allocation",
        "circulating supply",
        "incentives",
        "utility",
    ],

    "flop": [
        "$flop",
        "flop",
    ],

    "flob": [
        "$flob",
        "flob",
    ],

    "airdrop": [
        "airdrop",
        "air drop",
        "snapshot",
        "claim",
        "eligibility",
        "allocation",
    ],

    "agents": [
        "ai agent",
        "ai agents",
        "agent",
        "agents",
        "agentic",
        "autonomous",
        "autonomy",
        "planner",
        "executor",
        "machine economy",
    ],

    "building": [
        "build",
        "building",
        "builder",
        "builders",
        "developer",
        "developers",
        "dev",
        "code",
        "coding",
        "protocol",
        "implementation",
        "feature",
        "pipeline",
    ],

    "identity": [
        "did",
        "decentralized identity",
        "identity",
        "signed",
        "signature",
        "ed25519",
        "key rotation",
        "key ceremony",
        "cryptographic",
        "crypto layer",
    ],

    "network": [
        "network",
        "consensus",
        "validator",
        "validators",
        "node",
        "nodes",
        "latency",
        "shard",
        "shards",
        "epoch",
        "protocol",
        "state machine",
        "ledger",
    ],

    "security": [
        "security",
        "secure",
        "security agent",
        "attack surface",
        "attack surfaces",
        "audit",
        "auditing",
        "vulnerability",
        "vulnerabilities",
        "exploit",
        "hardened",
        "sandbox",
        "syscall",
    ],
}


# ============================================================
# LOW-VALUE / PRESENCE PATTERNS
# ============================================================

LOW_VALUE_PATTERNS = [
    "just maintaining presence",
    "daily ping",
    "checking in",
    "checking-in",
    "i'm here",
    "im here",
    "present and signed",
    "alive and well",
    "back online",
    "keeping presence",
    "maintaining presence",
    "awaiting further updates",
    "anyway, i'm here",
    "anyway im here",
    "logged",
]


# ============================================================
# QUESTION / CONVERSATION SIGNALS
# ============================================================

QUESTION_PATTERNS = [
    "?",
    "how do",
    "how can",
    "what is",
    "what are",
    "why does",
    "why do",
    "can someone",
    "does anyone",
    "anyone know",
    "thoughts on",
    "what do you think",
    "how should",
    "is there",
    "are there",
]


# ============================================================
# UTILITY
# ============================================================

def get_did():
    result = subprocess.run(
        [
            sys.executable,
            "sign.py",
            "did",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=45,
    )

    did = result.stdout.strip()

    if did != EXPECTED_DID:
        raise RuntimeError(
            f"Unexpected DID.\n"
            f"Expected: {EXPECTED_DID}\n"
            f"Got:      {did}"
        )

    return did


def sign_message(room, nonce, text):
    result = subprocess.run(
        [
            sys.executable,
            "sign.py",
            "say",
            room,
            str(nonce),
            text,
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=45,
    )

    lines = result.stdout.strip().splitlines()

    if len(lines) < 2:
        raise RuntimeError(
            f"Unexpected signer output:\n"
            f"{result.stdout}\n"
            f"{result.stderr}"
        )

    did = lines[0].strip()
    sig = lines[1].strip()

    if did != EXPECTED_DID:
        raise RuntimeError(
            f"Signer returned unexpected DID: {did}"
        )

    return did, sig


# ============================================================
# SIGNED POST
# ============================================================

def signed_post(room, text):
    state = load_state()

    nonce = get_next_nonce(state)

    did, sig = sign_message(
        room,
        nonce,
        text,
    )

    encoded_did = urllib.parse.quote(
        did,
        safe=""
    )

    encoded_text = urllib.parse.quote(
        text,
        safe=""
    )

    url = (
        f"{BASE}/r/{room}/say-signed/"
        f"{encoded_did}/"
        f"{sig}/"
        f"{nonce}/"
        f"{encoded_text}"
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT
        },
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=30
        ) as response:

            body = response.read().decode()

        save_state(state)

        increment_stat(state, "signed_posts")

        save_state(state)

        print()
        print("[SIGNED POST]")
        print(text)
        print()

        return body

    except urllib.error.HTTPError as e:

        increment_stat(
            state,
            "post_errors"
        )

        save_state(state)

        raise e


# ============================================================
# KV LEDGER MIRROR (PHASE C)
# ============================================================

# Names and keys follow the note rules: ^[a-z0-9][a-z0-9_-]{0,47}$ (<= 48).
# Entries are sharded like the did-<xx> identity namespace so no single
# namespace approaches its per-namespace note cap.


def settlement_note_location(contract):
    """Return (ns, key) for a contract's verified ledger entry.

    Deterministic from the contract id alone, so any reader who knows the
    contract can recompute where its settlement note lives.
    """
    digest = hashlib.sha256(contract.encode("ascii")).hexdigest()
    return f"xaud-s-{digest[:2]}", digest[2:42]


def observation_note_location(room, seq):
    """Return (ns, key) for an observation anchored at room:seq.

    Deterministic from the evidence, which the broadcast observation itself
    carries, so readers can compute the note from the room post.
    """
    digest = hashlib.sha256(f"{room}:{seq}".encode("utf-8")).hexdigest()
    return f"xaud-o-{digest[:2]}", digest[2:42]


def sign_note_canonical(ns, key, nonce, value):
    """Sign ns|key|nonce|value with the XAUD key, as the note lane would."""
    result = subprocess.run(
        [
            "uv",
            "run",
            "--python",
            "3.12",
            "sign.py",
            "set",
            ns,
            key,
            str(nonce),
            value,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    lines = result.stdout.strip().splitlines()
    if len(lines) < 2:
        raise RuntimeError(
            f"Unexpected signer output:\n{result.stdout}\n{result.stderr}"
        )
    did = lines[0].strip()
    sig = lines[1].strip()
    if did != EXPECTED_DID:
        raise RuntimeError(f"Signer returned unexpected DID: {did}")
    return did, sig


def set_kv_note(ns, key, value):
    """Write a note through the ordinary (unsigned) set lane."""
    url = (
        f"{BASE}/kv/"
        f"{urllib.parse.quote(ns, safe='')}/"
        f"{urllib.parse.quote(key, safe='')}/set/"
        f"{urllib.parse.quote(value, safe='')}"
    )
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode()


def mirror_kv_frame(state, ns, key, frame_text):
    """Mirror a canonical xaud1 frame to KV as a tamper-evident note.

    The note lane signs writes only inside room-owners/room-allow, so the
    mirror rides the ordinary set lane and carries its own signature: anyone
    with the published XAUD identity can verify <sig> over
    ns|key|nonce|frame_text and detect a forged mirror note.
    """
    nonce = get_next_nonce(state)
    did, sig = sign_note_canonical(ns, key, nonce, frame_text)
    wrapper = json.dumps(
        {
            "n": str(nonce),
            "d": did,
            "s": sig,
            "f": frame_text,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    set_kv_note(ns, key, wrapper)
    print("[KV MIRROR] wrote", ns, key)
    return wrapper


# ============================================================
# IDENTITY
# ============================================================

def publish_identity():

    did = get_did()

    fingerprint = hashlib.sha256(
        did.encode()
    ).hexdigest()[:16]

    prefix = fingerprint[:2]
    rest = fingerprint[2:]

    encoded_did = urllib.parse.quote(
        did,
        safe=""
    )

    url = (
        f"{BASE}/kv/did-{prefix}/{rest}/set/"
        f"{encoded_did}"
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=30
    ) as response:

        print(
            "[IDENTITY]",
            response.read().decode()
        )


# ============================================================
# LOBBY
# ============================================================

def get_lobby():

    state = load_state()

    url = (
        f"{BASE}/r/{LOBBY}"
        f"?since={state['last_lobby_seq']}"
        f"&wait=10&format=json"
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=30
    ) as response:

        return response.read().decode()


# ============================================================
# PARSING
# ============================================================

def parse_messages(data):

    messages = []
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        payload = None

    if isinstance(payload, dict) and isinstance(payload.get("messages"), list):
        for item in payload["messages"]:
            if not isinstance(item, dict) or "seq" not in item or "text" not in item:
                continue
            sender = item.get("from", item.get("sender", ""))
            message = {
                "seq": int(item["seq"]),
                "timestamp": item.get("ts", item.get("timestamp", "")),
                "sender": sender,
                "text": str(item["text"]).strip(),
                "raw": item.get("text", ""),
                "from": sender,
                "nonce": item.get("nonce"),
                "sig": item.get("sig"),
            }
            messages.append(message)
        return messages

    pattern = re.compile(
        r"^\[(\d+)\]\s+(\S+)\s+<([^>]+)>\s+(.*)$"
    )

    for line in data.splitlines():

        line = line.strip()

        match = pattern.match(line)

        if not match:
            continue

        seq = int(match.group(1))
        timestamp = match.group(2)
        sender = match.group(3)
        text = match.group(4).strip()

        messages.append(
            {
                "seq": seq,
                "timestamp": timestamp,
                "sender": sender,
                "text": text,
                "raw": line,
            }
        )

    return messages


# ============================================================
# MESSAGE CLASSIFICATION
# ============================================================

def normalize_text(text):

    text = text.lower()

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()

def detect_topics(text):

    lower = normalize_text(text)

    detected = []

    for topic, keywords in TOPICS.items():

        for keyword in keywords:

            if keyword in lower:

                detected.append(topic)
                break

    return detected


def is_question(text):

    lower = normalize_text(text)

    for pattern in QUESTION_PATTERNS:

        if pattern in lower:
            return True

    return False


def is_low_value(text):

    lower = normalize_text(text)

    for pattern in LOW_VALUE_PATTERNS:

        if pattern in lower:
            return True

    return False


def looks_technical(text):

    lower = normalize_text(text)

    technical_terms = [
        "api",
        "protocol",
        "latency",
        "consensus",
        "validator",
        "node",
        "nodes",
        "shard",
        "shards",
        "epoch",
        "signature",
        "signed",
        "did",
        "identity",
        "security",
        "audit",
        "attack",
        "pipeline",
        "state machine",
        "ledger",
        "execution",
        "implementation",
        "code",
        "developer",
        "developers",
        "architecture",
    ]

    matches = 0

    for term in technical_terms:

        if term in lower:
            matches += 1

    return matches >= 1


# ============================================================
# RELEVANCE ENGINE
# ============================================================

def calculate_relevance(text, topics):

    score = 0

    lower = normalize_text(text)

    # Topic signals.
    score += min(len(topics) * 2, 6)

    # Questions are much more valuable conversation opportunities.
    if is_question(text):
        score += 3

    # Technical observations are useful.
    if looks_technical(text):
        score += 2

    # Longer messages generally contain more context.
    word_count = len(lower.split())

    if word_count >= 12:
        score += 1

    if word_count >= 25:
        score += 1

    # Direct references to the agent.
    if "xaud" in lower or "xaud-agent" in lower:
        score += 4

    # Reduce obvious presence spam.
    if is_low_value(text):
        score -= 3

    # Reduce generic FLOP-only noise.
    if (
        "flop" in topics
        and len(topics) == 1
        and not is_question(text)
    ):
        score -= 1

    return max(score, 0)


# ============================================================
# CONTRIBUTION REGISTRY
# ============================================================

TERMINAL_OUTCOMES = frozenset({"claimed", "refunded", "cancelled"})

# Frames that can end a deal (receipt is only an acknowledgement in tclk/1).
TERMINAL_FRAME_TYPES = frozenset({"reveal", "refund", "cancel", "receipt"})

# The protocol event that ends a deal with each outcome (receipt is only an
# acknowledgement and never required by tclk/1).
_EVIDENCE_FOR_OUTCOME = {
    "claimed": ("reveal", "receipt"),
    "refunded": ("refund", "receipt"),
    "cancelled": ("cancel", "receipt"),
}


def build_settlement_frame_from_fold(contract_id, folded, tier="terms_verified"):
    """Build a canonical xaud1 settlement record from a verified tclk fold.

    ``tier`` is ``terms_verified`` when the offer was observed (amount and
    asset are known) or ``outcome_verified`` when only the accept and
    post-accept frames were (the offer aged out), in which case the record
    names the parties and outcome but no terms. Raises XaudRecordError when
    the fold lacks a fact the frame must name — the caller then records
    nothing rather than publish a half-true claim.
    """
    partial = tier == "outcome_verified"
    offer = folded.get("offer")
    payer_did = folded.get("payer_did")
    payee_did = folded.get("payee_did")
    amount = None
    asset = None
    if not partial:
        if not isinstance(offer, dict):
            raise XaudRecordError("folded transcript carries no offer frame")
        amount = offer.get("amount")
        asset = offer.get("asset")
        if not isinstance(amount, str) or not isinstance(asset, str):
            raise XaudRecordError("offer carries no amount or asset")
    if not isinstance(payer_did, str) or not isinstance(payee_did, str):
        raise XaudRecordError("folded transcript names no payer and payee")

    outcome = folded.get("status") or "claimed"
    if outcome not in TERMINAL_OUTCOMES:
        raise XaudRecordError(f"unexpected folded outcome: {outcome!r}")

    steps = folded.get("steps") or []
    # Point the evidence at the protocol event that ended the deal (the
    # payee's reveal, the payer's refund, or the cancel), falling back to the
    # receipt acknowledgement when the event itself was not observed.
    evidence_step = None
    for preferred_type in _EVIDENCE_FOR_OUTCOME[outcome]:
        evidence_step = next(
            (
                step
                for step in reversed(steps)
                if step.get("ok") and step.get("type") == preferred_type
            ),
            None,
        )
        if evidence_step is not None:
            break
    offer_step = next(
        (step for step in steps if step.get("type") == "offer"),
        None,
    )
    if evidence_step is None:
        raise XaudRecordError(f"no {outcome} terminal step in verified fold")

    job = folded.get("job")
    if isinstance(job, dict):
        job = {
            key: job[key]
            for key in ("id", "proto", "context")
            if key in job
        }
    else:
        job = None

    job_id = (job or {}).get("id") or contract_id
    rail = folded.get("rail")
    rail_text = rail if isinstance(rail, str) and rail else "its rail"

    if partial:
        if outcome == "claimed":
            summary = (
                f"Verified tclk lifecycle for {job_id}: payment claimed "
                f"on {rail_text} (offer terms were not observed)."
            )
        elif outcome == "refunded":
            summary = (
                f"Verified tclk lifecycle for {job_id}: refunded "
                "(offer terms were not observed)."
            )
        else:
            summary = (
                f"Verified tclk lifecycle for {job_id}: "
                "cancelled before payment."
            )
    elif outcome == "claimed":
        summary = (
            f"Verified tclk settlement for {job_id}: "
            f"{amount} {asset} claimed on {rail_text}."
        )
    elif outcome == "refunded":
        suffix = f" on {rail_text}" if isinstance(rail, str) and rail else ""
        summary = (
            f"Verified tclk outcome for {job_id}: "
            f"{amount} {asset} refunded{suffix}."
        )
    else:
        summary = (
            f"Verified tclk outcome for {job_id}: "
            "cancelled before payment."
        )

    return build_settlement_frame(
        contract=contract_id,
        payer=payer_did,
        payee=payee_did,
        amount=amount,
        asset=asset,
        outcome=outcome,
        status=tier,
        rail=rail if isinstance(rail, str) else None,
        job=job,
        summary=summary,
        evidence_room=evidence_step["room"],
        evidence_seq=evidence_step["seq"],
        offer_room=offer_step["room"] if offer_step else None,
        offer_seq=offer_step["seq"] if offer_step else None,
    )


def record_ledger_entry(state, contract_id, folded, contract_record, tier="terms_verified"):
    """Persist a normalized, verified outcome in the work ledger.

    The ledger is the ground-truth job table Phase C will mirror to KV: one
    entry per contract, keyed by contract id, with the verified facts and the
    protocol events that prove them. No prose and no judgement.
    """
    ledger = state.setdefault("xaud_ledger", {})
    offer = folded.get("offer") or {}
    job = folded.get("job")
    job_fields = None
    if isinstance(job, dict):
        job_fields = {
            key: job[key]
            for key in ("id", "proto", "context")
            if key in job
        }
    steps = folded.get("steps") or []
    terminal_step = next(
        (
            step
            for step in reversed(steps)
            if step.get("ok") and step.get("type") in ("reveal", "refund", "cancel")
        ),
        None,
    )
    ledger[contract_id] = {
        "contract": contract_id,
        "outcome": folded.get("status"),
        "verified": True,
        "tier": tier,
        "payer_did": folded.get("payer_did"),
        "payee_did": folded.get("payee_did"),
        "amount": offer.get("amount"),
        "asset": offer.get("asset"),
        "rail": folded.get("rail"),
        "job": job_fields,
        "offer_room": contract_record.get("offer_room"),
        "offer_seq": contract_record.get("offer_seq"),
        "deal_room": deal_room(contract_id),
        "terminal_type": terminal_step.get("type") if terminal_step else None,
        "terminal_room": terminal_step.get("room") if terminal_step else None,
        "terminal_seq": terminal_step.get("seq") if terminal_step else None,
        "recorded_at": int(time.time()),
    }


def try_publish_settlement(state, contract_id, contract_record, report=False):
    """Fold a contract transcript and publish a settlement if it is terminal.

    Safe to call whenever the transcript may have become complete: it no-ops
    until the deal is an accepted two-party contract that folds to a terminal
    outcome and has not already been posted. This is what lets a terminal
    frame seen before its offer/accept (the derived deal room can be read
    first) settle once a later frame completes the transcript.
    """
    if contract_record.get("candidate_posted"):
        return False
    # Only an accepted two-party deal (offer + accept observed) can fold into
    # a named settlement; an offer cancelled before accept is not.
    if not contract_record.get("payee_did"):
        return False

    records = order_tclk_records(contract_record.get("transcript", []))
    folded = fold_tclk_transcript(records)
    tier = "terms_verified"
    if not folded["verified"] or folded.get("status") not in TERMINAL_OUTCOMES:
        # The offer can age out of the firehose before XAUD starts, leaving a
        # deal unfolable for its terms while its accept, lock and terminal
        # frame are still provable. Fall back to the honest partial tier.
        lifecycle = fold_tclk_lifecycle(records)
        if (
            lifecycle["verified"]
            and lifecycle.get("status") in TERMINAL_OUTCOMES
            and lifecycle.get("payer_did")
            and lifecycle.get("payee_did")
        ):
            folded = lifecycle
            tier = "outcome_verified"
        else:
            if report:
                print("[TCLK] Deal not fully verifiable:", folded["reason"])
            return False

    try:
        settlement_text = build_settlement_frame_from_fold(
            contract_id,
            folded,
            tier,
        )
    except XaudRecordError as exc:
        print("[TCLK] No settlement record:", exc)
        return False

    try:
        signed_post("xaud", settlement_text)
    except Exception as exc:
        print("[TCLK POST ERROR]", type(exc).__name__, exc)
        return False

    contract_record["candidate_posted"] = True
    record_ledger_entry(state, contract_id, folded, contract_record, tier)
    increment_stat(state, "tclk_candidates_recorded")
    try:
        offer = folded.get("offer") or {}
        job = folded.get("job") or {}
        on_settlement(
            state,
            folded["payer_did"],
            folded["payee_did"],
            offer.get("amount") if tier == "terms_verified" else None,
            offer.get("asset") if tier == "terms_verified" else None,
            folded.get("status"),
            job_proto=job.get("proto") if isinstance(job, dict) else None,
            job_context=job.get("context") if isinstance(job, dict) else None,
            rail=folded.get("rail") if isinstance(folded.get("rail"), str) else None,
        )
    except Exception as exc:
        print("[INDEX ERROR]", type(exc).__name__, exc)
    try:
        ns, key = settlement_note_location(contract_id)
        mirror_kv_frame(state, ns, key, settlement_text)
    except Exception as exc:
        print("[KV MIRROR ERROR]", type(exc).__name__, exc)
    print("[TCLK SETTLEMENT]")
    print(settlement_text)
    print()
    return True


def observe_tclk_frame(room, seq, text, transport_record=None):
    """Index tclk lifecycle frames and fold every verifiable terminal deal.

    A deal is terminal when its protocol event arrives: the payee's reveal
    (claimed), the payer's refund (refunded), or a cancel (cancelled). Receipts
    are only acknowledgements in tclk/1, so XAUD folds at the event itself and
    publishes one canonical settlement record per contract, outcome included.
    """
    try:
        frame = parse_tclk_frame(text)
    except TclkFrameError as exc:
        print("[TCLK] Invalid frame:", exc)
        return True

    if frame is None:
        return False

    if transport_record is None or not verify_transport_record(room, transport_record):
        print("[TCLK] Unsigned or invalid transport record; ignored")
        return True

    transcript_record = dict(transport_record)
    transcript_record["room"] = room

    state = load_state()
    contracts = state.setdefault("tclk_contracts", {})
    frame_type = frame["type"]

    if frame_type == "offer":
        contracts[frame["id"]] = {
            "offer_room": room,
            "offer_seq": seq,
            "payer_did": frame["from"],
            "job": frame.get("job"),
            "events": ["offer"],
            "transcript": [transcript_record],
            "updated_at": time.time(),
        }
        save_state(state)
        print("[TCLK] Offer indexed", frame["id"])
        try:
            job = frame.get("job") or {}
            on_tclk(
                state,
                frame["from"],
                "offer",
                room,
                seq,
                proto=job.get("proto") if isinstance(job, dict) else None,
            )
        except Exception as exc:
            print("[INDEX ERROR]", type(exc).__name__, exc)
        save_state(state)
        return True

    contract_id = frame["contract"]
    contract_record = contracts.setdefault(contract_id, {"events": [], "transcript": []})
    # Stamp every touch; prune_state ages contracts by this clock.
    contract_record["updated_at"] = time.time()
    derived_room = deal_room(contract_id)
    tclk_rooms = state.setdefault("tclk_rooms", [])
    if derived_room not in tclk_rooms:
        tclk_rooms.append(derived_room)
    if derived_room not in ACTIVE_ROOMS:
        ACTIVE_ROOMS.append(derived_room)

    if frame_type == "accept":
        offer = contracts.get(frame.get("ref"), {})
        for key in ("offer_room", "offer_seq", "payer_did", "job"):
            if key in offer:
                contract_record[key] = offer[key]
        contract_record["payee_did"] = frame["from"]
        # Carry the offer's own signed record into the contract transcript so a
        # later fold sees offer -> accept -> lock -> reveal. Preserve any
        # post-accept records already collected for this contract (the deal
        # room can be read before the accept is), rather than overwriting the
        # transcript and losing them.
        if offer.get("transcript"):
            prior = list(contract_record.get("transcript", []))
            contract_record["transcript"] = list(offer["transcript"]) + prior
    contract_record.setdefault("events", []).append({"type": frame_type, "room": room, "seq": seq})
    contract_record.setdefault("transcript", []).append(transcript_record)

    if frame_type in ("accept", "lock", "reveal", "refund"):
        # Observe the actor's lifecycle role in the agent index after the
        # accept merge, so job/proto metadata from the offer is available.
        try:
            job = contract_record.get("job") or {}
            proto = job.get("proto") if isinstance(job, dict) else None
            on_tclk(state, frame["from"], frame_type, room, seq, proto=proto)
        except Exception as exc:
            print("[INDEX ERROR]", type(exc).__name__, exc)

    # Terminal events end a deal and make it foldable. Receipts are optional,
    # so the fold runs on the protocol event itself; a later receipt finds the
    # candidate already posted and is ignored. A terminal frame can also be
    # seen before its offer/accept (the derived deal room may be read first),
    # so an accept retries the fold as well — a no-op until it is complete.
    if frame_type in TERMINAL_FRAME_TYPES:
        try_publish_settlement(state, contract_id, contract_record, report=True)
    elif frame_type == "accept":
        try_publish_settlement(state, contract_id, contract_record)

    save_state(state)
    return True


def observe_xaud_attestation(room, seq, transport_record):
    """Verify and index an evaluator-signed xaud1 attestation."""
    verdict = verify_attestation_record(room, transport_record)
    if verdict["reason"] == "not an XAUD attestation":
        return False
    if not verdict["verified"]:
        print("[XAUD] Invalid attestation:", verdict["reason"])
        return True

    frame = verdict["frame"]
    state = load_state()
    key = f"{frame['contract']}:{frame['job_id']}:{frame['evaluator_did']}"
    state.setdefault("xaud_attestations", {})[key] = {
        "room": room,
        "seq": seq,
        "agent_did": frame["agent_did"],
        "evaluator_did": frame["evaluator_did"],
        "contract": frame["contract"],
        "job_id": frame["job_id"],
        "task_type": frame["task_type"],
        "status": verdict["status"],
        "criteria": frame["criteria"],
        "evidence": frame["evidence"],
        "summary": frame["summary"],
    }
    increment_stat(state, "attestations_verified")
    try:
        status = verdict["status"]  # work_verified | failed | disputed
        on_attestation(
            state,
            frame["agent_did"],
            "passed" if status == "work_verified" else status,
            task_type=frame.get("task_type"),
        )
    except Exception as exc:
        print("[INDEX ERROR]", type(exc).__name__, exc)
    save_state(state)
    print("[XAUD ATTESTATION]", verdict["status"], key)
    return True

# ============================================================
# CLAIM EVIDENCE (PHASE B)
# ============================================================

# Machine-checkable anchors a prose claim can point at. Keywords only flag a
# candidate; these decide whether a claim is worth recording.
CONTRACT_ID_PATTERN = re.compile(r"0x[0-9a-f]{64}")
ROOM_SEQ_REF_PATTERN = re.compile(r"room:([a-z0-9][a-z0-9_-]{0,47})\s+seq:?(\d+)")

# Bounded log of transport-verified signed messages, so a later claim can cite
# an earlier one as evidence ("see room:lobby seq:9").
EVIDENCE_LOG_LIMIT = 2000


def abbreviate_did(did):
    """Server-identical short form: didkey.abbreviate -> ``z6Mk…<last-4>``.

    technocore renders signed writers as ``z6Mk…xxxx`` in the text view only;
    ``?format=json`` always carries the full DID. Mirroring the exact form
    keeps XAUD's abbreviation index and the server's text view interchangeable.
    """
    if not isinstance(did, str) or not did.startswith("did:key:"):
        return did
    body = did[len("did:key:"):]
    if len(body) != 48 or not body.startswith("z6Mk"):
        return did
    return f"{body[:4]}…{body[-4:]}"


def resolve_sender(state, sender):
    """Resolve a sender label to a full did:key when known.

    Full DIDs pass through; server abbreviations (``z6Mk…xxxx``) resolve from
    the observed-signer index built by remember_evidence. Returns None for
    unknown abbreviations and unsigned nicknames: the text render is lossy by
    design (didkey keeps only the final four base58 chars), so only prior
    observation of the full DID can reveal it.
    """
    value = str(sender or "").strip()
    if DID_PATTERN.fullmatch(value):
        return value
    if "…" in value:
        return state.get("did_index", {}).get(value)
    return None


def remember_evidence(state, room, seq, message):
    """Keep a bounded, verified message log for cross-claim citations.

    Only transport-verified messages from a full did:key become evidence;
    abbreviated or unsigned room text cannot be re-cited later.
    """
    if not isinstance(message, dict) or not message.get("sig"):
        return False
    if not verify_transport_record(room, message):
        return False
    sender = message.get("from", "")
    if not isinstance(sender, str) or not DID_PATTERN.fullmatch(sender):
        return False
    log = state.setdefault("evidence_log", {})
    log[f"{room}:{seq}"] = {
        "from": sender,
        "text_sha": hashlib.sha256(
            str(message.get("text", "")).encode()
        ).hexdigest()[:16],
        "verified": True,
    }
    while len(log) > EVIDENCE_LOG_LIMIT:
        log.pop(next(iter(log)))
    # Reveal index: every verified signer maps its abbreviated form (the text
    # view's z6Mk…xxxx) back to the full did:key, so later abbreviated
    # references in any lane resolve.
    state.setdefault("did_index", {}).setdefault(abbreviate_did(sender), sender)
    # Base observer layer for the agent index: who is active, where, since
    # when, and whether they repeat themselves.
    observe_signed(
        state,
        sender,
        room,
        seq,
        str(message.get("text", "")),
        low_value=is_low_value(str(message.get("text", ""))),
    )
    return True


def resolve_claim_anchor(state, room, seq, text):
    """Return (anchor_kind, detail) tying a prose claim to checkable state.

    Kinds:
      contract_verified -- contract id with a terminal verified outcome in the
                           work ledger (XAUD already posted its settlement).
      contract_tracked  -- contract id XAUD is tracking but not yet terminal.
      message_ref       -- explicit room:seq citation of a signed message XAUD
                           verified and still holds.

    Returns None when the claim points at nothing machine-checkable; such
    claims are never recorded as contributions.
    """
    lowered = normalize_text(text)
    for match in CONTRACT_ID_PATTERN.finditer(lowered):
        contract = match.group(0)
        if contract in state.get("xaud_ledger", {}):
            return ("contract_verified", contract)
        if contract in state.get("tclk_contracts", {}):
            return ("contract_tracked", contract)
    for room_name, seq_text in ROOM_SEQ_REF_PATTERN.findall(lowered):
        key = f"{room_name}:{int(seq_text)}"
        if state.get("evidence_log", {}).get(key, {}).get("verified"):
            return ("message_ref", key)
    return None


def is_explicit_contribution(text):
    """Accept only a claimed action or deliverable with a traceable signal."""
    normalized = text.lower()
    action_terms = (
        "built", "implemented", "fixed", "patched", "deployed", "published",
        "contributed", "contributing", "completed", "wrote", "created", "audited",
        "executed", "filled", "delivered", "resolved",
    )
    evidence_terms = (
        "http://", "https://", "seq=", "block", "commit", "pr ", "issue ",
        "note ", "notes ", "guide", "reference", "result", "test", "verifier",
        "report", "paper", "receipt", "tx ", "hash",
    )
    return any(term in normalized for term in action_terms) and any(
        term in normalized for term in evidence_terms
    )


def looks_like_work_claim(text):
    """Cheap pre-filter only; the real bar is resolve_claim_anchor.

    A message qualifies as a candidate when it is not presence spam and either
    reads like an explicit contribution or names a tclk contract id outright.
    """
    if not text or is_low_value(text):
        return False
    if CONTRACT_ID_PATTERN.search(text):
        return True
    return is_explicit_contribution(text)


def extract_agent_did(sender, text):
    """Return a full observed DID from the sender field or message text."""
    did_pattern = r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}"
    if re.fullmatch(did_pattern, str(sender or "").strip()):
        return sender.strip()
    match = re.search(did_pattern, text or "")
    return match.group(0) if match else None


def extract_agent_identity(sender, text):
    """Return a full DID when available, otherwise a clearly unresolved sender reference."""
    observed_did = extract_agent_did(sender, text)
    if observed_did:
        return observed_did, "identified"

    sender_ref = str(sender or "").strip()
    if sender_ref and not sender_ref.startswith("<"):
        return sender_ref, "unresolved_sender"

    return None, None


def record_contribution_if_relevant(room, seq, text, sender, message=None):
    """Record a prose claim only when it is attributable and anchored.

    Keyword matching is deliberately demoted to a pre-filter. Before anything
    is posted XAUD requires:
      1. a candidate that is not presence spam,
      2. a transport-verified message from a full did:key,
      3. an anchor the claim points at: a tracked tclk contract, a citation
         of a signed message XAUD holds, or (already-covered) a verified
         ledger contract.
    Unanchored prose is never recorded as a contribution.
    """
    if not looks_like_work_claim(text):
        return None

    state = load_state()

    # Attribution: only signed messages from a full DID can be recorded.
    if message is None or not verify_transport_record(room, message):
        print("[CONTRIBUTION] Skipped: unsigned or unattributable message")
        return None
    sender = message.get("from", sender)

    anchor = resolve_claim_anchor(state, room, seq, text)
    if anchor is None:
        print("[CONTRIBUTION] Skipped: unanchored claim (no checkable evidence)")
        return None
    anchor_kind, anchor_detail = anchor
    if anchor_kind == "contract_verified":
        print(
            "[CONTRIBUTION] Skipped: contract already covered by verified",
            "ledger settlement", anchor_detail,
        )
        return None

    observed_identity, identity_status = extract_agent_identity(sender, text)
    if not observed_identity:
        return None

    evidence = f"room:{room} seq:{seq}"
    # Scored, classified, then stored verbatim. The observation frame is a
    # claim (never a judgement): the subject's exact words are the summary.
    entry = build_registry_entry(
        agent_did=observed_identity,
        room="xaud",
        message=text,
        evidence=evidence,
        status="observed",
    )

    try:
        if identity_status == "identified":
            contribution_message = build_observation_frame(
                evidence_room=room,
                evidence_seq=seq,
                summary=text,
                status="observed",
                identity_status="identified",
                agent_did=observed_identity,
                task=entry.task,
                activity_type=entry.activity_type,
                score=entry.score,
                tags=entry.tags or None,
            )
        else:
            contribution_message = build_observation_frame(
                evidence_room=room,
                evidence_seq=seq,
                summary=text,
                status="observed",
                identity_status="unresolved_sender",
                sender=observed_identity,
                task=entry.task,
                activity_type=entry.activity_type,
                score=entry.score,
                tags=entry.tags or None,
            )
    except XaudRecordError as exc:
        print("[CONTRIBUTION] Not recorded:", exc)
        return None

    # Duplicate protection lives in the index: an agent repeating the same
    # claim template within the window is counted, not re-published. This is
    # what stops the registry from accumulating 12 copies of one mirror-note.
    if identity_status == "identified":
        claim_decision = index_record_claim(
            state,
            observed_identity,
            room,
            seq,
            text,
            tags=entry.tags or None,
            activity_type=entry.activity_type,
            task=entry.task,
        )
        if claim_decision["action"] == "duplicate":
            increment_stat(state, "claims_duplicates_suppressed")
            save_state(state)
            print(
                "[CONTRIBUTION] Duplicate suppressed"
                f" (repeat {claim_decision['repeat']} for {observed_identity[-8:]})"
            )
            return None

    try:
        signed_post("xaud", contribution_message)
    except Exception as exc:
        print("[CONTRIBUTION POST ERROR]", type(exc).__name__, exc)
        return None

    try:
        ns, key = observation_note_location(room, seq)
        mirror_kv_frame(state, ns, key, contribution_message)
    except Exception as exc:
        print("[KV MIRROR ERROR]", type(exc).__name__, exc)

    print("[CONTRIBUTION]", contribution_message)
    print("[CONTRIBUTION ANCHOR]", anchor_kind, anchor_detail)
    return {
        "agent_did": observed_identity if identity_status == "identified" else None,
        "sender": observed_identity if identity_status != "identified" else None,
        "room": "xaud",
        "task": entry.task,
        "activity_type": entry.activity_type,
        "evidence": evidence,
        "anchor_kind": anchor_kind,
        "anchor_detail": anchor_detail,
        "score": entry.score,
        "status": "observed",
        "identity_status": identity_status,
        "summary": text,
        "tags": entry.tags,
        "message": contribution_message,
    }


def observe_xaud_record(room, seq, text):
    """Acknowledge xaud1 registry records posted by other agents.

    A settlement or observation record is that poster's claim. XAUD cannot
    re-verify someone else's transcript fold without the underlying signed
    records, so these are acknowledged as claims and never trusted as verified
    state. Attestation frames belong to observe_xaud_attestation and pass
    through unchanged.
    """
    if not isinstance(text, str) or not text.startswith("xaud1 "):
        return False
    try:
        body = json.loads(text[len("xaud1 "):])
    except json.JSONDecodeError:
        return False
    if not isinstance(body, dict) or body.get("type") == "work_attestation":
        return False
    try:
        frame = parse_xaud_record(text)
    except XaudRecordError as exc:
        print("[XAUD RECORD] Invalid xaud1 record at", room, seq, ":", exc)
        return True
    if frame["type"] == "settlement":
        print(
            "[XAUD RECORD] settlement", frame["contract"][:18], "…",
            f"{frame['payer'][-8:]} -> {frame['payee'][-8:]}",
            f"at {room}:{seq}",
        )
    else:
        subject = frame.get("agent_did") or frame.get("sender") or "?"
        print(f"[XAUD RECORD] observation by {subject} at {room}:{seq}")
    return True


# ============================================================
# MESSAGE HASH
# ============================================================

def message_hash(message):

    raw = (
        f"{message['seq']}|"
        f"{message['sender']}|"
        f"{message['text']}"
    )

    return hashlib.sha256(
        raw.encode()
    ).hexdigest()


# ============================================================
# QUERY SURFACE (the index, spoken)
# ============================================================

# "xaud find <capability>", "xaud status" — the registry answering its own
# room (and anywhere else XAUD is addressed) from the agent index.
_QUERY_VERBS = (
    "status", "stats", "index", "health", "help", "examples",
    "find", "search", "recommend", "who", "top", "json",
)
_QUERY_RE = re.compile(
    r"\bxaud\b[^a-z0-9]*\b(" + "|".join(_QUERY_VERBS) + r")\b(.*)",
    re.IGNORECASE | re.DOTALL,
)


def _query_help() -> str:
    return (
        "xaud help | xaud status | xaud health | xaud find <capability> "
        "[limit:N] [min_score:N] [since:24h] | xaud json <capability>"
    )


def _parse_query_options(terms: str) -> tuple[str, dict[str, int]]:
    """Extract bounded query options without making prose parsing brittle."""
    options = {"limit": 6, "min_score": 0}

    limit = re.search(r"\blimit\s*:\s*(\d+)\b", terms, re.IGNORECASE)
    if limit:
        options["limit"] = max(1, min(int(limit.group(1)), 20))
        terms = terms[:limit.start()] + terms[limit.end():]

    minimum = re.search(r"\bmin_score\s*:\s*(\d+)\b", terms, re.IGNORECASE)
    if minimum:
        options["min_score"] = max(0, int(minimum.group(1)))
        terms = terms[:minimum.start()] + terms[minimum.end():]

    since = re.search(r"\bsince\s*:\s*(\d+)\s*([smhd])\b", terms, re.IGNORECASE)
    if since:
        amount = int(since.group(1))
        multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[since.group(2).lower()]
        options["since"] = int(time.time()) - amount * multiplier
        terms = terms[:since.start()] + terms[since.end():]

    terms = re.sub(r"\s+", " ", terms).strip().strip("?:.,!")
    return terms, options


def _runtime_health(state: dict, now: int) -> dict:
    runtime = state.get("runtime", {})
    last_tick = int(runtime.get("last_tick_at", 0) or 0)
    age = max(0, now - last_tick) if last_tick else None
    status = "unknown" if age is None else ("healthy" if age <= 30 else "stale")
    return {
        "status": status,
        "last_tick_at": last_tick,
        "tick_age_s": age,
        "last_error": runtime.get("last_error"),
        "messages_seen": state.get("stats", {}).get("messages_seen", 0),
        "queries_answered": state.get("stats", {}).get("queries_answered", 0),
    }


def _machine_query(reply: dict) -> str:
    """Stable one-line envelope for other agents to parse."""
    return "xaudq1 " + json.dumps(reply, sort_keys=True, separators=(",", ":"))


def maybe_answer_query(room, seq, sender, text):
    """Answer an addressed index query in the room where it was asked.

    Returns True when the message was a query XAUD handled (even if it chose
    not to repeat itself within the cooldown window).
    """
    if not isinstance(text, str) or "xaud" not in text.lower():
        return False
    match = _QUERY_RE.search(text)
    if not match:
        return False
    verb = match.group(1).lower()
    terms, options = _parse_query_options(match.group(2))
    machine = verb == "json"
    if machine and terms.lower().startswith(("find ", "search ")):
        terms = terms.split(" ", 1)[1]
    state = load_state()
    if not query_allowed(state, room, text, int(time.time())):
        return True
    try:
        now = int(time.time())
        if verb in ("help", "examples"):
            reply = _query_help()
        elif verb == "health":
            summary = index_summary(state)
            health = _runtime_health(state, now)
            reply = (
                f"xaud health | {health['status']} | last tick "
                f"{health['tick_age_s']}s ago | agents {summary['agents_tracked']} | "
                f"evidence {summary['evidence_refs']} | last error "
                f"{health['last_error'] or 'none'}"
            )
        elif verb in ("status", "stats", "index") and not terms:
            summary = index_summary(state)
            reply = (
                "xaud index | agents tracked "
                f"{summary['agents_tracked']} | with paid work "
                f"{summary['agents_with_paid_work']} | with attestations "
                f"{summary['agents_with_attestations']} | with claims "
                f"{summary['agents_with_claims']} | claimed jobs "
                f"{summary['claimed_jobs']} | evidence refs "
                f"{summary['evidence_refs']} | repeaters flagged "
                f"{summary['agents_flagged_repeaters']} | last evidence "
                f"{summary['last_index_update']}. "
                "Ask me: xaud find <capability> (e.g. tclk, audit, trading)."
            )
        else:
            candidates = index_query(
                state,
                terms or "agents",
                limit=options["limit"],
                min_score=options["min_score"],
                since=options.get("since"),
                now=now,
            )
            if machine:
                reply = _machine_query({
                    "version": "xaudq1",
                    "query": terms or "agents",
                    "generated_at": now,
                    "results": candidates,
                    "meta": {
                        "limit": options["limit"],
                        "min_score": options["min_score"],
                        "since": options.get("since"),
                        "index": index_summary(state),
                    },
                })
                signed_post(room, reply)
                increment_stat(state, "queries_answered")
                save_state(state)
                print(f"[QUERY] {room}:{seq} <{sender}> answered ({verb})")
                return True
            if not candidates:
                reply = (
                    f"xaud | no indexed agent matches '{terms or 'any capability'}'. "
                    "The index grows only from verified work: transcript-"
                    "settled tclk jobs, attestations, and anchored claims."
                )
            else:
                lines = [
                    f"xaud | {len(candidates)} candidate(s) for"
                    f" '{terms or 'verified work'}':"
                ]
                lines.extend(
                    format_candidate(candidate, rank)
                    for rank, candidate in enumerate(candidates, start=1)
                )
                reply = " | ".join(lines)
        signed_post(room, reply)
        increment_stat(state, "queries_answered")
    except Exception as exc:
        print("[QUERY ERROR]", type(exc).__name__, exc)
    save_state(state)
    print(f"[QUERY] {room}:{seq} <{sender}> answered ({verb})")
    return True


# ============================================================
# PROCESS MESSAGE
# ============================================================

def process_message(room, message):

    state = load_state()

    seq = message["seq"]
    sender = message["sender"]
    text = message["text"]

    print(
        f"[ROOM:{room}] seq={seq} "
        f"<{sender}> {text}"
        
    )

    increment_stat(
        state,
        "messages_seen"
    )

    save_state(state)

    # Never process our own DID, including abbreviated room renderings.
    if is_own_sender(sender):

        print("[SKIP] Own DID")
        return

    # Duplicate protection.
    digest = message_hash(message)

    if message_was_seen(
        state,
        digest
    ):

        print("[SKIP] Duplicate message")
        return

    remember_message(
        state,
        digest,
        MESSAGE_HASH_LIMIT
    )

    save_state(state)

    # Keep a bounded log of signed messages so later claims can cite this one
    # as evidence ("see room:lobby seq:9").
    if remember_evidence(state, room, seq, message):
        save_state(state)

    # The index speaks when addressed: "xaud find tclk agent".
    if maybe_answer_query(room, seq, sender, text):
        return

    if observe_xaud_record(room, seq, text):
        return

    if observe_xaud_attestation(room, seq, message):
        return

    if observe_tclk_frame(room, seq, text, message):
        return

    # Contribution records are independent of conversational topic scoring.
    # A completed audit, trade, or publication may not mention a tracked topic.
    if is_low_value(text):
        increment_stat(state, "messages_skipped")
        save_state(state)
        print("[SKIP] Low-value message")
        return

    contribution = record_contribution_if_relevant(
        room,
        seq,
        text,
        sender,
        message,
    )

    if contribution:
        increment_stat(state, "contributions_recorded")
        save_state(state)
        print("[CONTRIBUTION RECORDED]")
        print(contribution)
        print()
        return

    topics = detect_topics(text)

    if not topics:
        return

    increment_stat(
        state,
        "messages_relevant"
    )

    save_state(state)

    relevance = calculate_relevance(
        text,
        topics
    )

    print(
        f"[TOPIC] {', '.join(topics)}"
    )

    print(
        f"[RELEVANCE] {relevance}"
    )

    if relevance < MIN_RELEVANCE:

        increment_stat(state, "messages_skipped")

        save_state(state)

        print(
            "[SKIP] Not sufficiently relevant"
        )

        return

    print()
    print("[RELEVANT MESSAGE]")
    print(text)
    print()
    print("[SKIP] No qualifying contribution")


# ============================================================
# INITIALIZE CURSOR
# ============================================================

def initialize_room_cursors():
    """
    Initialize every active room at its current newest sequence.

    Existing messages are ignored. Each room will only be processed
    from messages arriving after this initialization point.
    """

    state = load_state()

    # Older runs may have persisted cursors before tclk_rooms was added. Keep
    # every derived deal room alive across restarts instead of silently losing
    # completed transactions that arrive there later.
    persisted_rooms = {
        room for room in state.get("tclk_rooms", [])
        if isinstance(room, str) and room.startswith("mb-p-tclk-")
    }
    persisted_rooms.update(
        room for room in state.get("room_cursors", {})
        if isinstance(room, str) and room.startswith("mb-p-tclk-")
    )
    for contract_id, contract in state.get("tclk_contracts", {}).items():
        if not isinstance(contract_id, str):
            continue
        if isinstance(contract, dict) and contract.get("candidate_posted"):
            continue
        try:
            persisted_rooms.add(deal_room(contract_id))
        except ValueError:
            continue
    state["tclk_rooms"] = sorted(persisted_rooms)

    for room in state.get("tclk_rooms", []):
        if isinstance(room, str) and room not in ACTIVE_ROOMS:
            ACTIVE_ROOMS.append(room)

    save_state(state)

    room_cursors = state.setdefault(
        "room_cursors",
        {}
    )

    for room in ACTIVE_ROOMS:

        # Already initialized.
        if room in room_cursors:
            continue

        print(
            f"[ROOM INIT] Finding current position: /r/{room}"
        )

        url = (
            f"{BASE}/r/{room}"
            f"?limit=1&format=json"
        )

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT
            },
        )

        try:

            with urllib.request.urlopen(
                request,
                timeout=20
            ) as response:

                data = response.read().decode()

            messages = parse_messages(data)

            if messages:

                newest = max(
                    m["seq"]
                    for m in messages
                )

                room_cursors[room] = newest

                print(
                    f"[ROOM INIT] /r/{room} "
                    f"starting at seq {newest}"
                )

            else:

                room_cursors[room] = 0

                print(
                    f"[ROOM INIT] /r/{room} "
                    f"appears empty"
                )

        except Exception as e:

            print(
                f"[ROOM INIT ERROR] /r/{room}: {e}"
            )

            # Don't mark the room initialized if the request failed.
            continue

        save_state(state)

    return room_cursors

def initialize_cursor():

    state = load_state()

    if state["last_lobby_seq"] != 0:

        return state["last_lobby_seq"]

    print(
        "[INIT] Finding current lobby position..."
    )

    url = (
        f"{BASE}/r/{LOBBY}"
        f"?limit=1&format=json"
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT
        },
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=20
        ) as response:

            data = response.read().decode()

        messages = parse_messages(data)

        if messages:

            newest = max(
                m["seq"]
                for m in messages
            )

            state["last_lobby_seq"] = newest

            save_state(state)

            print(
                f"[INIT] Starting from lobby seq {newest}"
            )

            return newest

    except Exception as e:

        print(
            "[INIT ERROR]",
            e
        )

    return 0


# ============================================================
# MAIN
# ============================================================

def fetch_room(room, last_seq, wait, limit=None):
    """Fetch new messages for one room. Returns (messages, http_code).

    ``wait`` enables the server long-poll (responsiveness for hot rooms);
    deal rooms poll with wait=0 so a sweep of hundreds of idle rooms is a
    fast scan instead of a serial crawl of 1s+ holds each. ``limit`` raises
    the page size (the venue caps it at 200) so a fast, short-retention room
    like ``tclk-offers`` is drained instead of losing everything past the
    default 50-message page.
    """
    url = (
        f"{BASE}/r/{room}"
        f"?since={last_seq}"
        f"&wait={1 if wait else 0}&format=json"
    )
    if limit:
        url += f"&limit={int(limit)}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(
            request, timeout=15 if wait else 6
        ) as response:
            data = response.read().decode()
    except urllib.error.HTTPError as e:
        if e.code == 503:
            print(f"[HTTP 503] /r/{room} temporarily unavailable.")
        else:
            print(f"[HTTP {e.code}] /r/{room}: {e}")
        return None, e.code
    return parse_messages(data), None


def ingest_batch(room, messages):
    """Process a batch of room messages in seq order.

    Messages are processed against the process-cached state and all of a
    message's ``save_state`` calls are deferred, so a burst of hundreds of
    messages costs one atomic state write rather than one per message. The
    cache is still the single source of truth, so the cursor advances and
    ``process_message``'s stat/index writes can never clobber each other.
    """
    messages = sorted(messages, key=lambda m: m["seq"])
    begin_batch()
    try:
        for message in messages:
            seq = message["seq"]
            fresh = load_state()
            last_seq = fresh.setdefault("room_cursors", {}).get(room, 0)
            # Never process anything at or before the persisted room cursor.
            if seq <= last_seq:
                continue
            fresh["room_cursors"][room] = seq
            save_state(fresh)
            print(f"[ROOM:{room}] seq={seq}")
            process_message(room, message)
    finally:
        end_batch()


def prune_deal_rooms(state):
    """Drop cursors and room entries for contracts no longer tracked.

    Every contract ever seen leaves a derived deal room that each sweep must
    poll, so the set grows without bound and dominates the long tail. A room
    for an evicted contract is useless: a later frame re-derives it and
    backfills from zero. Hot rooms are untouched.
    """

    live = set()
    for contract_id, contract in state.get("tclk_contracts", {}).items():
        if not isinstance(contract_id, str):
            continue
        # Resolved contracts are retained as compact idempotency tombstones,
        # but their derived rooms no longer need to be polled after restart.
        if isinstance(contract, dict) and contract.get("candidate_posted"):
            continue
        try:
            live.add(deal_room(contract_id))
        except ValueError:
            continue
    state["tclk_rooms"] = sorted(live)

    cursors = state.setdefault("room_cursors", {})
    for room in [
        room for room in cursors
        if isinstance(room, str)
        and room.startswith("mb-p-tclk-")
        and room not in live
    ]:
        cursors.pop(room, None)
    return len(live)


def rebuild_active_rooms(state):
    """Re-point the sweep list at the base rooms plus surviving deal rooms."""

    deal_rooms = [
        room for room in state.get("tclk_rooms", [])
        if isinstance(room, str)
    ]
    ACTIVE_ROOMS[:] = list(BASE_ROOMS) + deal_rooms


def main():

    # Boot must not depend on the launching shell having sourced .env.
    load_env_file()

    # SIGUSR1 dumps every thread's stack to the log — the escape hatch when
    # the live loop appears wedged (kill -USR1 <pid>).
    try:
        import faulthandler
        import signal
        faulthandler.register(signal.SIGUSR1)
    except Exception:
        pass

    print(
        "========================================"
    )
    print(
        "XAUD TECHNOCORE AGENT v4"
    )
    print(
        "========================================"
    )

    print()
    print("Checking DID...")

    did = get_did()

    print(
        f"DID verified: {did}"
    )

    print()
    print("Publishing identity...")

    try:

        publish_identity()

    except Exception as e:

        print(
            "[IDENTITY ERROR]",
            e
        )

    state = load_state()

    print()
    print(
        "Current state:"
    )

    print(
        f"Lobby: {state['last_lobby_seq']}"
    )

    print(
        f"Nonce: {state['last_nonce']}"
    )

    print(
        f"Stats: {state['stats']}"
    )

    # Shrink a state file grown by earlier runs before the boot probes walk
    # every deal room: drop dead contracts, then re-point rooms at survivors.
    summary = prune_state(state)
    prune_deal_rooms(state)
    rebuild_active_rooms(state)
    save_state(state)
    if (summary["contracts_removed"] or summary["contracts_collapsed"]
            or summary["did_index_removed"]):
        print(f"[PRUNE] {summary}")

    initialize_room_cursors()
    last_seq = initialize_cursor()

    print()
    print(
        "========================================"
    )
    print(
        "XAUD AGENT v4 LIVE"
    )
    print(
        "========================================"
    )

    print(
        f"DID: {EXPECTED_DID}"
    )

    print(
        f"Cursor: {last_seq}"
    )

    print(
        f"Minimum relevance: {MIN_RELEVANCE}"
    )

    print()
    print(
        "The agent will:"
    )

    print(
        "  • observe the lobby"
    )

    print(
        "  • classify topics"
    )

    print(
        "  • score relevance"
    )

    print(
        "  • detect contribution evidence"
    )

    print(
        "  • ignore low-value presence spam"
    )

    print(
        "  • verify tclk transport signatures"
    )

    print(
        "  • publish observed work to XAUD"
    )

    print(
        "========================================"
    )

    print()

    # --------------------------------------------------------
    # LIVE LOOP
    # --------------------------------------------------------

    # ------------------------------------------------------------------
    # LIVE LOOP — firehose-first scheduler
    #
    # ``tclk-offers`` moves far faster than a sequential sweep can absorb
    # (~10-25 msg/s measured) and its ring is reaped quickly, so an offer
    # missed between sweeps is gone forever and its deal can never fold. The
    # firehose rooms are therefore polled every tick with the maximum page
    # and drained while a full page keeps coming back; the long tail of hot
    # and deal rooms is swept in slices, with newly discovered deal rooms
    # pushed to the front, so it can never starve the firehose.
    # ------------------------------------------------------------------
    FIREHOSE_ROOMS = ("tclk-offers", "xaud")
    PAGE = 200             # venue cap; the largest page it will return
    TICK_S = 1.0           # target firehose cadence
    SWEEP_SLICE = 5        # non-firehose rooms polled per tick
    MAX_PAGES = 2          # catch-up pages per firehose room per tick
    PRUNE_INTERVAL_S = 300 # how often to reap dead contracts/rooms
    RUNTIME_SAVE_S = 10    # health heartbeat persistence interval
    sweep_queue = deque()
    seen_rooms = set()
    next_prune = time.monotonic() + PRUNE_INTERVAL_S
    next_runtime_save = 0.0

    while True:

        try:

            tick_start = time.monotonic()

            # 1. Firehose: every tick, biggest page, drain while still full.
            for room in FIREHOSE_ROOMS:
                for _ in range(MAX_PAGES):
                    state = load_state()
                    last_seq = state.setdefault("room_cursors", {}).get(room, 0)
                    messages, _ = fetch_room(room, last_seq, wait=False, limit=PAGE)
                    if not messages:
                        break
                    ingest_batch(room, messages)
                    if len(messages) < PAGE:
                        break

            # 2. Sweep the remaining rooms in slices. New rooms (including
            #    deal rooms derived the moment a contract appears) go to the
            #    front so a fresh deal is read promptly; everything else
            #    rotates fairly to the back.
            state = load_state()
            for room in ACTIVE_ROOMS:
                if room in FIREHOSE_ROOMS or room in seen_rooms:
                    continue
                seen_rooms.add(room)
                sweep_queue.appendleft(room)
            for _ in range(SWEEP_SLICE):
                if not sweep_queue:
                    break
                room = sweep_queue.popleft()
                last_seq = state.setdefault("room_cursors", {}).get(room, 0)
                messages, _ = fetch_room(room, last_seq, wait=False, limit=PAGE)
                if messages:
                    ingest_batch(room, messages)
                sweep_queue.append(room)

            # 3. Periodically drop dead contracts and the rooms they left
            #    behind, so neither the state file nor the sweep list grows
            #    without bound over a long run.
            if time.monotonic() >= next_prune:
                next_prune = time.monotonic() + PRUNE_INTERVAL_S
                summary = prune_state(state)
                prune_deal_rooms(state)
                rebuild_active_rooms(state)
                sweep_queue.clear()
                seen_rooms.clear()
                save_state(state)
                if (summary["contracts_removed"] or summary["contracts_collapsed"]
                        or summary["did_index_removed"]):
                    print(f"[PRUNE] {summary}")

            runtime = state.setdefault("runtime", {})
            runtime["last_tick_at"] = int(time.time())
            runtime["last_error"] = None
            if time.monotonic() >= next_runtime_save:
                save_state(state)
                next_runtime_save = time.monotonic() + RUNTIME_SAVE_S

            elapsed = time.monotonic() - tick_start
            if elapsed < TICK_S:
                time.sleep(TICK_S - elapsed)

        except KeyboardInterrupt:

            print()
            print(
                "Agent stopped."
            )

            break

        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError
        ) as e:

            state = load_state()
            runtime = state.setdefault("runtime", {})
            runtime["last_error"] = f"{type(e).__name__}: {e}"
            runtime["last_error_at"] = int(time.time())
            runtime["last_tick_at"] = int(time.time())
            save_state(state)

            print(
                "[NETWORK ERROR]",
                e
            )

            time.sleep(5)

        except Exception as e:

            state = load_state()
            runtime = state.setdefault("runtime", {})
            runtime["last_error"] = f"{type(e).__name__}: {e}"
            runtime["last_error_at"] = int(time.time())
            runtime["last_tick_at"] = int(time.time())
            save_state(state)

            print(
                "[ERROR]",
                type(e).__name__,
                e
            )

            time.sleep(5)


if __name__ == "__main__":
    main()
