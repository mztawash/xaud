#!/usr/bin/env python3
"""Conservative participant for FLOP Labs' Technocore Close Call contest."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = os.environ.get("TECHNOCORE_URL", "https://technocore.chat")
SEASON = "close-1"
TRADING_ROOM = "close1"
PRICE_ROOM = "d-close1-price"
POSITIONS_ROOM = "d-close1-positions"
FLOW_ROOM = "d-close1-flow"
STATE_FILE = Path(os.environ.get("CLOSE_CALL_STATE", "close_call_state.json"))
DID_RE = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")
BASE_FEE_RATE = 0.01
DEFAULT_MAX_POSITION = 20.0
DEFAULT_MAX_TRADE_QTY = 5.0


def load_local_env() -> None:
    """Load simple KEY=VALUE settings without overriding the shell."""
    env_file = Path(__file__).with_name(".env")
    if not env_file.exists():
        return
    for raw in env_file.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


def max_position() -> float:
    return max(0.0, float(os.environ.get("CLOSE_CALL_MAX_POSITION", str(DEFAULT_MAX_POSITION))))


def max_trade_qty() -> float:
    return max(0.1, float(os.environ.get("CLOSE_CALL_MAX_TRADE_QTY", str(DEFAULT_MAX_TRADE_QTY))))


def expected_edge_for_side(position_side: str, price: float, reference: float, forecast: float) -> tuple[bool, float]:
    """Fee is 1% of price. Require about 1.5% of edge to the forecast, not 6%."""
    fee = BASE_FEE_RATE * price
    expected_pnl = forecast - price if position_side == "buy" else price - forecast
    required = fee + 0.005 * price
    return expected_pnl >= required, expected_pnl - required


def expected_edge_when_taker(maker_side: str, price: float, reference: float, forecast: float) -> tuple[bool, float]:
    return expected_edge_for_side("buy" if maker_side == "sell" else "sell", price, reference, forecast)


def b58(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value = int.from_bytes(data, "big")
    output = ""
    while value:
        value, remainder = divmod(value, 58)
        output = alphabet[remainder] + output
    return output


def load_signer() -> tuple[Ed25519PrivateKey, str]:
    load_local_env()
    seed = os.environ.get("SIGN_SEED")
    if not seed:
        env_file = Path(__file__).with_name(".env")
        for line in env_file.read_text().splitlines():
            if line.startswith("export SIGN_SEED="):
                seed = line.split("=", 1)[1].strip().strip("\"'")
                break
    if not seed or len(seed) != 64:
        raise RuntimeError("SIGN_SEED must be a 64-character hex Ed25519 seed")
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    did = "did:key:z" + b58(b"\xed\x01" + key.public_key().public_bytes_raw())
    if not DID_RE.fullmatch(did):
        raise RuntimeError("derived DID is malformed")
    return key, did


def sign(key: Ed25519PrivateKey, text: str) -> str:
    return base64.urlsafe_b64encode(key.sign(text.encode())).decode().rstrip("=")


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {
            "nonce": int(time.time() * 1000),
            "offers": {},
            "trades": {},
            "seen_trades": {},
            "position": 0.0,
            "pending_position": 0.0,
            "unreconciled_probe_gross_qty": 0.0,
            "risk_model": 2,
        }
    state = json.loads(STATE_FILE.read_text())
    state.setdefault("offers", {})
    state.setdefault("trades", {})
    state.setdefault("seen_trades", {})
    state.setdefault("unreconciled_probe_gross_qty", 0.0)
    if state.get("risk_model") != 2:
        state["position"] = 0.0
        state["pending_position"] = 0.0
        state["risk_model"] = 2
    state.setdefault("pending_position", 0.0)
    return state


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n")


def get_json(path: str) -> dict:
    attempt = 0
    while True:
        request = urllib.request.Request(BASE + path, headers={"User-Agent": "close-call-agent/1"})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, TimeoutError) as error:
            attempt += 1
            delay = min(5 * attempt, 60)
            print(f"network read failed ({error}); retrying in {delay}s", flush=True)
            time.sleep(delay)


def post_signed(key: Ed25519PrivateKey, did: str, state: dict, text: str, dry_run: bool) -> None:
    state["nonce"] = max(int(state.get("nonce", 0)) + 1, int(time.time() * 1000))
    nonce = str(state["nonce"])
    signature = sign(key, f"{TRADING_ROOM}|{nonce}|{text}")
    if dry_run:
        print(f"DRY_RUN {TRADING_ROOM} {text}")
        return
    body = json.dumps({"did": did, "sig": signature, "nonce": nonce, "text": text}).encode()
    attempt = 0
    while True:
        request = urllib.request.Request(
            f"{BASE}/r/{TRADING_ROOM}",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "close-call-agent/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                response.read()
            break
        except (urllib.error.URLError, TimeoutError) as error:
            attempt += 1
            delay = min(5 * attempt, 60)
            print(f"network post failed ({error}); retrying in {delay}s", flush=True)
            time.sleep(delay)
    save_state(state)


def referee_position(did: str) -> float | None:
    """Position from the latest referee top-10, or None if this DID is not listed."""
    body = get_json(f"/r/{POSITIONS_ROOM}?format=json&since=0&limit=5")
    messages = body.get("messages") or []
    if not messages:
        return None
    try:
        payload = json.loads(messages[-1]["text"])
    except (KeyError, TypeError, json.JSONDecodeError):
        return None
    if payload.get("t") != "positions":
        return None
    for row in payload.get("top") or []:
        if isinstance(row, (list, tuple)) and len(row) >= 2 and row[0] == did:
            try:
                return float(row[1])
            except (TypeError, ValueError):
                return None
    return None


def flow_outcomes() -> tuple[int, set[str], dict[str, str]]:
    """Latest flow page. Settled entries are trade ids. Void entries are [id, reason]."""
    body = get_json(f"/r/{FLOW_ROOM}?format=json&since=0&limit=50")
    settled: set[str] = set()
    void: dict[str, str] = {}
    oldest = 0
    for message in body.get("messages") or []:
        try:
            payload = json.loads(message["text"])
        except (KeyError, TypeError, json.JSONDecodeError):
            continue
        if payload.get("t") != "flow":
            continue
        try:
            sweep_n = int(payload.get("n") or 0)
        except (TypeError, ValueError):
            sweep_n = 0
        if sweep_n and (not oldest or sweep_n < oldest):
            oldest = sweep_n
        for item in payload.get("settled") or []:
            if isinstance(item, str):
                settled.add(item)
        for item in payload.get("void") or []:
            if isinstance(item, (list, tuple)) and len(item) >= 2 and isinstance(item[0], str):
                void[str(item[0])] = str(item[1])
    return oldest, settled, void


def apply_flow(state: dict, oldest_flow_sweep: int, settled: set[str], void: dict[str, str]) -> bool:
    """Apply settled and void. Return True while a reserved take is still inside the visible flow."""
    waiting = False
    position = float(state.get("position") or 0.0)
    pending = float(state.get("pending_position") or 0.0)
    for trade_id, trade in state.get("trades", {}).items():
        if not isinstance(trade, dict):
            continue
        status = trade.get("status")
        if status in ("settled", "void", "unseen"):
            continue
        qty = float(trade.get("qty") or 0.0)
        delta = qty if trade.get("own_side") == "buy" else -qty
        reserved = bool(trade.get("reserved"))
        if trade_id in settled:
            trade["status"] = "settled"
            trade["reserved"] = False
            if reserved:
                position = round(position + delta, 2)
                pending = round(pending - delta, 2)
            print(f"settled {trade_id} {trade.get('own_side')} qty={qty:.2f}", flush=True)
        elif trade_id in void:
            trade["status"] = "void"
            trade["void_reason"] = void[trade_id]
            trade["reserved"] = False
            if reserved:
                pending = round(pending - delta, 2)
            print(f"void {trade_id} reason={void[trade_id]}", flush=True)
        elif oldest_flow_sweep and int(trade.get("sweep") or 0) and int(trade["sweep"]) < oldest_flow_sweep:
            trade["status"] = "unseen"
            trade["reserved"] = False
            if reserved:
                pending = round(pending - delta, 2)
            print(
                f"unseen {trade_id} sweep={trade.get('sweep')} left the flow without settled or void",
                flush=True,
            )
        else:
            waiting = True
            print(f"waiting {trade_id} {trade.get('own_side')} qty={qty:.2f} sweep={trade.get('sweep')}", flush=True)
    state["position"] = round(position, 2)
    state["pending_position"] = round(pending, 2)
    return waiting


def order_cap(state: dict) -> float:
    """One contract until the referee has settled one of ours. Then the normal cap."""
    proved = any(
        isinstance(trade, dict) and trade.get("status") == "settled"
        for trade in state.get("trades", {}).values()
    )
    if proved:
        return max_trade_qty()
    return min(1.0, max_trade_qty())


def latest_price() -> tuple[int, float, float, float]:
    body = get_json(f"/r/{PRICE_ROOM}?format=json&since=0&limit=20")
    messages = body.get("messages", [])
    if not messages:
        raise RuntimeError("referee price room is empty")
    payload = json.loads(messages[-1]["text"])
    if payload.get("t") == "seed":
        sweep = int(payload["for"])
        price = float(payload["price"])
        limits = payload["limits"]
    else:
        sweep = int(payload["n"])
        price = float(payload["ref"]["px"])
        limits = payload["limits"]
    return sweep, price, float(limits[0]), float(limits[1])


def terms_json(terms: dict) -> str:
    return json.dumps(terms, sort_keys=True, separators=(",", ":"))


def make_offer(
    key: Ed25519PrivateKey,
    did: str,
    state: dict,
    price: float,
    side: str,
    qty: float,
    until: int,
    dry_run: bool,
) -> None:
    offer_id = f"xaud-{int(time.time() * 1000)}-{side}"
    terms = {
        "id": offer_id,
        "maker": did,
        "px": f"{price:.2f}",
        "qty": f"{qty:.2f}",
        "side": side,
        "taker": "any",
        "until": until,
    }
    maker_sig = sign(key, f"{SEASON}|terms|{terms_json(terms)}")
    state["offers"][offer_id] = terms
    text = json.dumps({
        "how": f"countersign {SEASON}|accept|{terms_json(terms)}|<your did:key> then POST t=trade",
        "maker_sig": maker_sig,
        "season": SEASON,
        "t": "offer",
        "terms": terms,
    }, separators=(",", ":"))
    post_signed(key, did, state, text, dry_run)


def accept_offers(
    key: Ed25519PrivateKey,
    did: str,
    state: dict,
    messages: list[dict],
    sweep: int,
    reference: float,
    forecast: float | None,
    unreconciled_probe: bool,
    cap: float,
    dry_run: bool,
) -> None:
    if forecast is None:
        print("no CLOSE_CALL_FORECAST_FINAL_PRICE; not accepting offers", flush=True)
        return
    for message in messages:
        try:
            offer = json.loads(message["text"])
        except (KeyError, json.JSONDecodeError):
            continue
        if offer.get("t") != "offer" or offer.get("season") != SEASON:
            continue
        terms = offer.get("terms")
        maker = terms.get("maker") if isinstance(terms, dict) else None
        if not isinstance(terms, dict) or maker == did or terms.get("taker") not in ("any", did):
            continue
        side = terms.get("side")
        if side not in ("buy", "sell"):
            continue
        try:
            qty = float(terms["qty"])
        except (KeyError, TypeError, ValueError):
            continue
        if qty <= 0 or qty > cap:
            continue
        price = float(terms.get("px", 0))
        if price <= 0:
            continue
        edge_ok, edge_after_stress = expected_edge_when_taker(side, price, reference, forecast)
        if not edge_ok:
            continue
        own_delta = -qty if side == "buy" else qty
        if unreconciled_probe:
            # No reliable old baseline exists. Permit at most one tiny
            # additional counter-sign in gross size, never make offers.
            if state.get("unreconciled_probe_gross_qty", 0.0) + qty > cap:
                continue
        else:
            projected = (
                state.get("position", 0.0)
                + state.get("pending_position", 0.0)
                + own_delta
            )
            if abs(projected) > max_position():
                continue
        trade_id = terms.get("id")
        if not isinstance(trade_id, str) or trade_id in state["trades"]:
            continue
        if not isinstance(terms.get("until"), int) or sweep > terms["until"]:
            continue
        maker_sig = offer.get("maker_sig")
        if not isinstance(maker_sig, str):
            continue
        taker_sig = sign(key, f"{SEASON}|accept|{terms_json(terms)}|{did}")
        trade = {
            "maker_sig": maker_sig,
            "season": SEASON,
            "taker": did,
            "taker_sig": taker_sig,
            "t": "trade",
            "terms": terms,
        }
        post_signed(key, did, state, json.dumps(trade, separators=(",", ":")), dry_run)
        state["trades"][trade_id] = {
            "seq": message.get("seq"),
            "sweep": sweep,
            "own_side": "sell" if side == "buy" else "buy",
            "qty": qty,
            "status": "pending",
            "reserved": not dry_run,
        }
        state["pending_position"] = round(
            state.get("pending_position", 0.0) + own_delta, 2
        )
        if unreconciled_probe:
            state["unreconciled_probe_gross_qty"] = round(
                state.get("unreconciled_probe_gross_qty", 0.0) + qty, 2
            )
        print(
            f"{'DRY_RUN ' if dry_run else ''}accepted offer id={trade_id} "
            f"maker={maker} side={side} qty={terms.get('qty')} px={terms.get('px')} "
            f"forecast_edge_after_stress={edge_after_stress:.4f}",
            flush=True,
        )
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="inspect without publishing (default)")
    mode.add_argument("--live", action="store_true", help="publish only after reconciliation and forecast gates pass")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    load_local_env()
    key, did = load_signer()
    live = args.live
    dry_run = not live
    forecast_raw = os.environ.get("CLOSE_CALL_FORECAST_FINAL_PRICE", "").strip()
    forecast = float(forecast_raw) if forecast_raw else None
    if forecast is not None and forecast <= 0:
        raise SystemExit("CLOSE_CALL_FORECAST_FINAL_PRICE must be positive")

    state = load_state()
    unreconciled_probe = False
    allow_unreconciled_live = False
    if live:
        if forecast is None:
            raise SystemExit("live trading blocked: set CLOSE_CALL_FORECAST_FINAL_PRICE")
        unreconciled_probe = os.environ.get("CLOSE_CALL_RECONCILED") != "1"
        allow_unreconciled_live = os.environ.get("CLOSE_CALL_ALLOW_UNRECONCILED_LIVE") == "1"
        if unreconciled_probe:
            if os.environ.get("CLOSE_CALL_UNRECONCILED_PROBE") != "1" and not allow_unreconciled_live:
                raise SystemExit("live trading blocked: reconcile accepted IDs or explicitly enable the one-trade probe")
            if allow_unreconciled_live:
                print(
                    f"WARNING: unreconciled account; explicit live mode enabled with capped trade size {max_trade_qty():.2f}; maker offers are allowed only at the current forecast edge",
                    flush=True,
                )
            else:
                print(
                    f"WARNING: unreconciled account; probe cap is {max_trade_qty():.2f} gross contracts total; no maker offers will be posted",
                    flush=True,
                )
        else:
            baseline_position = os.environ.get("CLOSE_CALL_BASELINE_POSITION")
            baseline_cash = os.environ.get("CLOSE_CALL_BASELINE_FREE_POLF")
            if baseline_position is not None:
                position = float(baseline_position)
                source = "env"
            else:
                looked_up = referee_position(did)
                if looked_up is not None:
                    position = looked_up
                    source = "referee"
                else:
                    position = float(state.get("position") or 0.0)
                    source = "local"
            state["position"] = position
            if baseline_cash is not None:
                state["free_polf"] = float(baseline_cash)
            state["reconciled_baseline_key"] = f"{position:.4f}:{source}"
            pending = float(state.get("pending_position") or 0.0)
            print(f"live position {position:.2f} pending {pending:.2f} from {source}", flush=True)
    else:
        unreconciled_probe = False
        # Dry-run calculations must never mutate authoritative local trading state.
        state = copy.deepcopy(state)

    body = get_json(f"/r/{TRADING_ROOM}?format=json&since=0&limit=200")
    registered = bool(state.get("registered"))
    if not registered:
        for message in body.get("messages", []):
            try:
                payload = json.loads(message["text"])
            except (KeyError, json.JSONDecodeError):
                continue
            if payload.get("t") == "owner" and payload.get("key") == did:
                registered = True
                state["registered"] = True
                break
    if not registered:
        text = json.dumps({"key": did, "season": SEASON, "t": "owner"}, separators=(",", ":"))
        post_signed(key, did, state, text, dry_run)
        state["registered"] = True
        print(f"registered {did}")

    sweep, reference, lower, upper = latest_price()
    oldest_flow, settled_ids, void_ids = flow_outcomes()
    waiting = apply_flow(state, oldest_flow, settled_ids, void_ids)
    if forecast is None:
        print("no final-price forecast configured; observing only, no offers accepted or quoted", flush=True)
        print(f"sweep={sweep} reference={reference:.2f} band={lower:.2f}..{upper:.2f}", flush=True)
        if live:
            save_state(state)
        return

    cap = order_cap(state)
    if waiting:
        print("waiting on the referee for an open take; no new offer or quote", flush=True)
    else:
        accept_offers(
            key, did, state, body.get("messages", []), sweep, reference,
            forecast, unreconciled_probe, cap, dry_run,
        )
    open_take = any(
        isinstance(trade, dict) and trade.get("status") == "pending" and trade.get("reserved")
        for trade in state.get("trades", {}).values()
    )
    # Quote the reference on the forecast side only, once per sweep.
    quote = round(reference, 2)
    position = round(state.get("position", 0.0) + state.get("pending_position", 0.0), 2)
    max_pos = max_position()
    qty = min(cap, max(0.0, max_pos - abs(position)))
    qty = float(f"{qty:.2f}")
    can_quote = (
        not waiting
        and not open_take
        and (not unreconciled_probe or allow_unreconciled_live)
        and state.get("last_quote_sweep") != sweep
    )
    if can_quote and qty >= 0.1:
        if forecast > reference and position + qty <= max_pos:
            make_offer(key, did, state, quote, "buy", qty, sweep + 2, dry_run)
            print(f"{'DRY_RUN ' if dry_run else ''}posted buy px={quote:.2f} qty={qty:.2f}", flush=True)
        elif forecast < reference and position - qty >= -max_pos:
            make_offer(key, did, state, quote, "sell", qty, sweep + 2, dry_run)
            print(f"{'DRY_RUN ' if dry_run else ''}posted sell px={quote:.2f} qty={qty:.2f}", flush=True)
        state["last_quote_sweep"] = sweep
    if live:
        save_state(state)
    print(f"{'DRY_RUN ' if dry_run else ''}sweep={sweep} reference={reference:.2f} band={lower:.2f}..{upper:.2f} forecast={forecast:.2f} position_estimate={position:.2f} max_position={max_pos:.2f}", flush=True)
    if not args.once:
        print("run with a scheduler every five minutes; no background loop is started by this script")


if __name__ == "__main__":
    main()
