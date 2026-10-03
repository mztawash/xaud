#!/usr/bin/env python3
"""Reconcile the Close Call participant against the referee's sweep archive.

The script is read-only unless called with ``--apply``. It verifies the
referee's signed price-room file hashes, checks archive bytes against the
archive index (and the signed file hash for non-redacted sweeps), and matches
all locally recorded maker offers/taker trades against the sweeps where they
could have settled. Public-room participant trades are not redacted by the
archive. Any missing or inconsistent evidence aborts before state is changed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import gzip
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import close_call_agent as participant
from tclk_observer import verify_transport_record

ARCHIVE = "https://challenges.technocore.chat/close-1"
PRICE_ROOM = "d-close1-price"
MAX_WORKERS = 8


def get_bytes(url: str) -> tuple[bytes, str | None]:
    error: Exception | None = None
    for attempt in range(4):
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "close-call-archive-reconciler/1", "Accept-Encoding": "gzip"},
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                return response.read(), response.headers.get("Content-Encoding")
        except (urllib.error.URLError, TimeoutError) as exc:
            error = exc
            if attempt < 3:
                time.sleep(1 + attempt)
    raise RuntimeError(f"GET failed after retries: {url}: {error}")


def get_json(url: str) -> dict[str, Any]:
    body, encoding = get_bytes(url)
    if encoding == "gzip":
        body = gzip.decompress(body)
    value = json.loads(body)
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object from {url}")
    return value


def get_archive_record(entry: dict[str, Any]) -> tuple[int, dict[str, Any], int]:
    path = entry.get("path")
    if not isinstance(path, str) or path.startswith("/") or ".." in Path(path).parts:
        raise RuntimeError(f"unsafe archive path for sweep {entry.get('n')}")
    raw, encoding = get_bytes(f"{ARCHIVE}/{path}")
    if encoding == "gzip":
        raw = gzip.decompress(raw)
    if len(raw) != entry.get("bytes"):
        raise RuntimeError(f"sweep {entry.get('n')}: archive byte-count mismatch")
    digest = hashlib.sha256(raw).hexdigest()
    if entry.get("status") == "full":
        if digest != entry.get("file"):
            raise RuntimeError(f"sweep {entry.get('n')}: full archive hash mismatch")
    elif entry.get("status") == "redacted":
        if digest != entry.get("sha256"):
            raise RuntimeError(f"sweep {entry.get('n')}: redacted archive hash mismatch")
    else:
        raise RuntimeError(f"sweep {entry.get('n')}: unsupported archive status")
    record = json.loads(raw)
    if not isinstance(record, dict):
        raise RuntimeError(f"sweep {entry.get('n')}: archive record is not an object")
    return int(entry["n"]), record, int(entry.get("redacted", 0))


def load_verified_price_files() -> dict[int, str]:
    body, encoding = get_bytes(f"https://technocore.chat/r/{PRICE_ROOM}/export")
    if encoding == "gzip":
        body = gzip.decompress(body)
    files: dict[int, str] = {}
    for line_no, raw_line in enumerate(body.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            message = json.loads(raw_line)
            payload = json.loads(message.get("text", "{}"))
        except (json.JSONDecodeError, TypeError, AttributeError) as exc:
            raise RuntimeError(f"price export line {line_no} is malformed: {exc}") from exc
        if payload.get("t") != "price":
            continue
        if not verify_transport_record(PRICE_ROOM, message):
            raise RuntimeError(f"price export line {line_no} has an invalid referee signature")
        sweep = payload.get("n")
        file_hash = payload.get("file")
        if type(sweep) is not int or not isinstance(file_hash, str):
            raise RuntimeError(f"price export line {line_no} lacks a sweep/file hash")
        previous = files.get(sweep)
        if previous is not None and previous != file_hash:
            raise RuntimeError(f"conflicting signed price records for sweep {sweep}")
        files[sweep] = file_hash
    if not files:
        raise RuntimeError("no signed price records were available")
    return files


def _offer_candidates(offers: dict[str, Any]) -> set[int]:
    candidates: set[int] = set()
    for offer_id, terms in offers.items():
        if not isinstance(terms, dict) or terms.get("id") != offer_id:
            raise RuntimeError(f"malformed locally persisted offer {offer_id!r}")
        try:
            until = int(terms["until"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"offer {offer_id!r} has no valid until sweep") from exc
        # The maker posts after reading the preceding reference. A countersigned
        # trade can be applied in either of the two sweeps before its expiry.
        candidates.update(n for n in (until - 1, until) if n > 0)
    return candidates


def _taker_candidates(trades: dict[str, Any]) -> set[int]:
    candidates: set[int] = set()
    for trade_id, trade in trades.items():
        if not isinstance(trade, dict):
            raise RuntimeError(f"malformed local trade row {trade_id!r}")
        sweep = trade.get("sweep")
        if type(sweep) is int:
            # Trades are posted after reading the current sweep. Allow for the
            # referee reading them on the next few sweeps if its room scan lags.
            candidates.update(range(sweep + 1, sweep + 4))
    return candidates


def _apply_fold_trade(
    lots: list[list[Decimal]], cash: Decimal, side: int,
    qty: Decimal, price: Decimal, fee: Decimal,
) -> Decimal:
    """Mirror the canonical fold's FIFO collateral and realized cash rules."""
    cash -= fee
    left = qty
    while left > 0 and lots and lots[0][0] * side < 0:
        lot_qty, lot_price = lots[0]
        size = min(left, abs(lot_qty))
        cash += size * price if side < 0 else size * (2 * lot_price - price)
        left -= size
        if size == abs(lot_qty):
            lots.pop(0)
        else:
            lots[0][0] = lot_qty + side * size
    if left > 0:
        cash -= left * price
        lots.append([side * left, price])
    return cash


def scan_archive(
    state: dict[str, Any],
    did: str,
    apply: bool,
) -> dict[str, Any]:
    index = get_json(f"{ARCHIVE}/index.json")
    if index.get("contest") not in (None, "close-1"):
        raise RuntimeError("archive index is for an unexpected contest")
    raw_entries = index.get("sweeps")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise RuntimeError("archive index has no sweep records")
    entries: dict[int, dict[str, Any]] = {}
    for entry in raw_entries:
        if isinstance(entry, dict) and type(entry.get("n")) is int:
            entries[entry["n"]] = entry
    latest_sweep = max(entries)

    offers = state.get("offers", {})
    local_trades = state.get("trades", {})
    if not isinstance(offers, dict) or not isinstance(local_trades, dict):
        raise RuntimeError("local offer/trade state is malformed")
    maker_ids = set(offers)
    taker_ids = set(local_trades)
    candidates = _offer_candidates(offers) | _taker_candidates(local_trades)
    # Check the first few sweeps too: the owner may have minted before its
    # earliest locally retained offer.
    earliest = min(candidates) if candidates else latest_sweep
    candidates.update(range(1, min(earliest, 16)))
    # The archive tail after the last locally tracked order window is also
    # checked for activity from this DID that may have been posted externally.
    last_local_window = max(candidates) if candidates else 0
    candidates.update(range(last_local_window + 1, latest_sweep + 1))
    candidates = {n for n in candidates if n <= latest_sweep}
    missing = sorted(n for n in candidates if n not in entries)
    if missing:
        raise RuntimeError(f"archive index is missing candidate sweeps: {missing[:12]}")

    signed_files = load_verified_price_files()
    for sweep in candidates:
        entry = entries[sweep]
        if signed_files.get(sweep) != entry.get("file"):
            raise RuntimeError(f"sweep {sweep}: archive hash is not anchored by the signed referee price room")

    archive_records: dict[int, dict[str, Any]] = {}
    redacted_total = 0
    failures: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(get_archive_record, entries[n]): n for n in sorted(candidates)}
        for count, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            expected_n = futures[future]
            sweep, record, redacted = future.result()
            if sweep != expected_n:
                raise RuntimeError(f"requested sweep {expected_n}, archive returned {sweep}")
            event = record.get("input")
            output = record.get("output")
            if not isinstance(event, dict) or not isinstance(output, dict):
                raise RuntimeError(f"sweep {sweep}: missing input/output records")
            if event.get("t") != "sweep" or event.get("n") != sweep or output.get("sweep") != sweep:
                raise RuntimeError(f"sweep {sweep}: archive sweep number mismatch")
            input_trades = event.get("trades")
            output_trades = output.get("trades")
            if not isinstance(input_trades, list) or not isinstance(output_trades, list):
                raise RuntimeError(f"sweep {sweep}: trade arrays malformed")
            if len(input_trades) != len(output_trades):
                raise RuntimeError(f"sweep {sweep}: input/output trade count mismatch")
            redacted_in_input = sum(
                isinstance(row, dict) and row.get("redacted") == "private room"
                for row in input_trades
            )
            if redacted_in_input != redacted:
                raise RuntimeError(f"sweep {sweep}: redacted trade count mismatch")
            archive_records[sweep] = record
            redacted_total += redacted
            if count % 25 == 0 or count == len(futures):
                print(f"verified {count}/{len(futures)} referee sweep records", flush=True)

    own_settlements: dict[str, dict[str, Any]] = {}
    settled_events: list[dict[str, Any]] = []
    settled_ids: set[str] = set()
    owner_sweeps: list[int] = []
    for sweep in sorted(archive_records):
        record = archive_records[sweep]
        event = record["input"]
        output = record["output"]
        if did in (event.get("owners") or []):
            owner_sweeps.append(sweep)
        for incoming, verdict in zip(event["trades"], output["trades"]):
            if not isinstance(incoming, dict):
                continue
            maker = incoming.get("maker")
            countersigner = incoming.get("countersigner")
            if maker != did and countersigner != did:
                continue
            trade_id = incoming.get("id")
            if not isinstance(trade_id, str) or not isinstance(verdict, dict):
                failures.append(f"sweep {sweep}: malformed participant trade")
                continue
            if trade_id in own_settlements and own_settlements[trade_id]["outcome"] == "settled":
                continue
            qty_text = incoming.get("qty")
            try:
                qty = Decimal(qty_text)
            except (InvalidOperation, TypeError):
                failures.append(f"sweep {sweep}: invalid participant trade quantity")
                continue
            if qty <= 0 or incoming.get("side") not in ("buy", "sell"):
                failures.append(f"sweep {sweep}: malformed participant trade terms")
                continue
            maker_delta = qty if incoming["side"] == "buy" else -qty
            delta = (maker_delta if maker == did else Decimal(0))
            delta += (-maker_delta if countersigner == did else Decimal(0))
            outcome = verdict.get("outcome")
            if outcome not in ("settled", "void"):
                failures.append(f"sweep {sweep}: unknown trade outcome for {trade_id}")
                continue
            event_row = {
                "trade_id": trade_id,
                "sweep": sweep,
                "maker": maker,
                "countersigner": countersigner,
                "qty": str(qty),
                "side": incoming["side"],
                "price": incoming.get("px"),
                "maker_fee": verdict.get("maker_fee", "0"),
                "taker_fee": verdict.get("taker_fee", "0"),
            }
            if outcome == "settled" and trade_id not in settled_ids:
                settled_events.append(event_row)
                settled_ids.add(trade_id)
            own_settlements[trade_id] = {
                "sweep": sweep,
                "outcome": outcome,
                "own_delta": str(delta if outcome == "settled" else Decimal(0)),
                "maker": maker,
                "countersigner": countersigner,
                "qty": str(qty),
                "side": incoming["side"],
                "price": incoming.get("px"),
                "maker_fee": event_row["maker_fee"],
                "taker_fee": event_row["taker_fee"],
            }
    if failures:
        raise RuntimeError("participant trade validation failed: " + "; ".join(failures[:10]))

    unmatched_taker_ids = sorted(taker_ids - own_settlements.keys())
    unmatched_maker_ids = sorted(maker_ids - own_settlements.keys())
    # No private-room participant trades are produced by this bot. Every own
    # maker offer is posted to close1, and every accepted taker trade is also
    # posted to close1. Thus an absent ID after its complete settlement window
    # means no participant position change; a redacted private-room row cannot
    # hide any of these known public-room IDs.
    position = sum(
        (Decimal(row["own_delta"]) for row in own_settlements.values() if row["outcome"] == "settled"),
        Decimal(0),
    )
    if position.as_tuple().exponent < -2:
        raise RuntimeError(f"computed position violates the 0.01 contract step: {position}")

    cash = Decimal("10000")
    lots: list[list[Decimal]] = []
    for row in settled_events:
        try:
            qty = Decimal(row["qty"])
            price = Decimal(row["price"])
            maker_fee = Decimal(row["maker_fee"])
            taker_fee = Decimal(row["taker_fee"])
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise RuntimeError(f"settled trade {row['trade_id']} has invalid fee/price data") from exc
        maker_side = 1 if row["side"] == "buy" else -1
        if row["maker"] == did and row["countersigner"] == did:
            cash -= maker_fee + taker_fee
        elif row["maker"] == did:
            cash = _apply_fold_trade(lots, cash, maker_side, qty, price, maker_fee)
        elif row["countersigner"] == did:
            cash = _apply_fold_trade(lots, cash, -maker_side, qty, price, taker_fee)
    lot_position = sum((lot[0] for lot in lots), Decimal(0))
    if lot_position != position:
        raise RuntimeError(f"FIFO position {lot_position} disagrees with net trade deltas {position}")

    result = {
        "did": did,
        "latest_archive_sweep": latest_sweep,
        "candidate_sweeps": len(candidates),
        "signed_price_hashes_verified": len(candidates),
        "full_or_redacted_archive_records_verified": len(archive_records),
        "redacted_private_trade_rows_in_candidates": redacted_total,
        "participant_owner_mints_seen": owner_sweeps,
        "participant_trade_ids_found": len(own_settlements),
        "participant_settled_trade_ids": sum(row["outcome"] == "settled" for row in own_settlements.values()),
        "participant_void_trade_ids": sum(row["outcome"] == "void" for row in own_settlements.values()),
        "local_taker_ids_without_archive_match_count": len(unmatched_taker_ids),
        "local_taker_ids_without_archive_match_sample": unmatched_taker_ids[:8],
        "local_maker_offers_without_archive_match_count": len(unmatched_maker_ids),
        "position": str(position.quantize(Decimal("0.01"))),
        "free_polf": str(cash.quantize(Decimal("0.01"))),
        "open_lot_count": len(lots),
        "archive_sweep_count_complete": all(n in archive_records for n in candidates),
        "applied": apply,
    }
    if not result["archive_sweep_count_complete"]:
        raise RuntimeError("archive candidate coverage is incomplete")
    if not owner_sweeps:
        raise RuntimeError("the participant DID was not found in any checked referee mint sweep")

    if apply:
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        state["position"] = float(position.quantize(Decimal("0.01")))
        state["pending_position"] = 0.0
        state["reconciled_baseline_key"] = f"{position.quantize(Decimal('0.0001')):.4f}:archive-{latest_sweep}"
        state["reconciled_baseline_position"] = float(position.quantize(Decimal("0.01")))
        state["free_polf"] = float(cash.quantize(Decimal("0.01")))
        state["reconciled_baseline_free_polf"] = float(cash.quantize(Decimal("0.01")))
        state["reconciled_baseline_sweep"] = latest_sweep
        state["archive_reconciled_sweep"] = latest_sweep
        state["archive_settled_trade_ids"] = sorted(
            trade_id for trade_id, row in own_settlements.items()
            if row.get("outcome") == "settled"
        )
        state["reconciliation"] = {
            "source": "challenges.technocore.chat close-1 referee archive",
            "verified_price_room": PRICE_ROOM,
            "latest_sweep": latest_sweep,
            "completed_at": now,
            "archive_records_checked": len(archive_records),
            "signed_price_hashes_checked": len(candidates),
            "redacted_archives_checked": sum(
                entries[n].get("status") == "redacted" for n in candidates
            ),
            "maker_offers_matched": len(maker_ids & own_settlements.keys()),
            "taker_trades_matched": len(taker_ids & own_settlements.keys()),
        }
        for trade_id, row in state["trades"].items():
            if not isinstance(row, dict):
                continue
            settled = own_settlements.get(trade_id)
            if settled:
                row["status"] = settled["outcome"]
                row["settled_sweep"] = settled["sweep"]
                row["reserved"] = False
            else:
                row["status"] = "unseen"
                row["reserved"] = False
        for trade_id, row in own_settlements.items():
            if trade_id in state["trades"]:
                continue
            own_side = "buy" if Decimal(row["own_delta"]) > 0 else "sell"
            if Decimal(row["own_delta"]) == 0:
                own_side = "flat"
            state["trades"][trade_id] = {
                "qty": float(row["qty"]),
                "own_side": own_side,
                "status": row["outcome"],
                "reserved": False,
                "sweep": row["sweep"],
                "settled_sweep": row["sweep"],
                "archive_reconciled": True,
            }
        path = participant.STATE_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        backup = path.with_suffix(path.suffix + ".pre-archive-reconcile")
        if path.exists() and not backup.exists():
            shutil.copy2(path, backup)
        fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        result["backup"] = str(backup) if backup.exists() else None
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write verified reconciliation into participant state")
    args = parser.parse_args()
    try:
        key, did = participant.load_signer()
        del key
        state = participant.load_state()
        result = scan_archive(state, did, args.apply)
    except Exception as exc:
        print(f"reconciliation failed closed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())