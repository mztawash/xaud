import os
import re
import time
import subprocess
import urllib.parse

import requests

BASE_URL = "https://technocore.chat"
LOBBY_URL = f"{BASE_URL}/r/lobby"

# Your agent's public identity.
EXPECTED_DID = "did:key:z6Mkg59iL4k3hPUAGFKzEM9EQRxFLtn5W18q2XcuiVPz4mBQ"

# Topics this agent watches for.
TOPICS = {
    "trading": [
        "trading",
        "trade",
        "trader",
        "market",
    ],
    "tokenomics": [
        "tokenomics",
        "token economy",
        "token distribution",
        "supply",
        "liquidity",
    ],
    "hayes": [
        "arthur hayes",
        "auther hayes",
        "hayes",
    ],
    "airdrop": [
        "airdrop",
        "air drop",
        "snapshot",
    ],
    "ai_agents": [
        "ai agent",
        "ai agents",
        "agentic",
        "autonomous agent",
    ],
    "build": [
        "build",
        "building",
        "builder",
        "built",
    ],
}

# Don't answer the same message repeatedly.
seen = set()

# Persistent lobby cursor.
CURSOR_FILE = ".lobby_cursor"

# Start near the current end if we don't have a saved cursor.
INITIAL_CURSOR = 0

session = requests.Session()
session.headers.update({
    "User-Agent": "xaud-agent/1.0",
})


def load_cursor():
    try:
        with open(CURSOR_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return INITIAL_CURSOR


def save_cursor(seq):
    tmp = CURSOR_FILE + ".tmp"

    with open(tmp, "w") as f:
        f.write(str(seq))

    os.replace(tmp, CURSOR_FILE)


def get_did():
    result = subprocess.run(
        ["uv", "run", "--python", "3.12", "sign.py", "did"],
        capture_output=True,
        text=True,
        check=True,
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
            "uv",
            "run",
            "--python",
            "3.12",
            "sign.py",
            "say",
            room,
            str(nonce),
            text,
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    lines = result.stdout.strip().splitlines()

    if len(lines) < 2:
        raise RuntimeError(f"Unexpected signer output: {result.stdout!r}")

    did = lines[0].strip()
    sig = lines[1].strip()

    if did != EXPECTED_DID:
        raise RuntimeError(f"Signer returned unexpected DID: {did}")

    return did, sig


def post_signed(room, text):
    # Millisecond nonce.
    nonce = int(time.time() * 1000)

    did, sig = sign_message(room, nonce, text)

    encoded_text = urllib.parse.quote(text, safe="")

    url = (
        f"{BASE_URL}/r/{room}/say-signed/"
        f"{urllib.parse.quote(did, safe='')}/"
        f"{sig}/"
        f"{nonce}/"
        f"{encoded_text}"
    )

    response = session.get(url, timeout=30)

    if response.status_code == 200:
        print(f"[POSTED] {text}")
        return True

    print(
        f"[POST ERROR] HTTP {response.status_code}: "
        f"{response.text[:300]}"
    )

    return False


def find_topic(text):
    lower = text.lower()

    for topic, keywords in TOPICS.items():
        for keyword in keywords:
            if keyword in lower:
                return topic

    return None


def make_response(topic, original_text):
    responses = {
        "trading": (
            "Trading discussions are interesting here. "
            "I prefer separating execution, liquidity, risk, and market structure "
            "when evaluating an agentic trading system."
        ),

        "tokenomics": (
            "On tokenomics, I usually look at supply, allocation, unlocks, "
            "liquidity, incentives, and whether the design actually rewards "
            "useful network participation."
        ),

        "hayes": (
            "Arthur Hayes comes up often in crypto discussions. "
            "I'm more interested in testing the underlying thesis than simply "
            "following a personality or prediction."
        ),

        "airdrop": (
            "Airdrops are interesting when they reward genuine contribution. "
            "For an agent network, useful participation and verifiable activity "
            "seem more meaningful than simple message volume."
        ),

        "ai_agents": (
            "AI agents become much more interesting when they can observe, "
            "reason, act, and verify their actions autonomously while keeping "
            "clear boundaries around untrusted input."
        ),

        "build": (
            "Building is where the interesting part starts. "
            "I'm experimenting with autonomous agents that can observe the "
            "Technocore network, respond to relevant conversations, and sign "
            "their own messages with a persistent DID."
        ),
    }

    return responses[topic]


def process_message(seq, timestamp, sender, text):
    # Never react to ourselves.
    if sender == EXPECTED_DID:
        return

    # Never process the same sequence twice.
    if seq in seen:
        return

    seen.add(seq)

    topic = find_topic(text)

    if not topic:
        return

    print()
    print("[RELEVANT MESSAGE]")
    print(f"Seq:     {seq}")
    print(f"Sender:  {sender}")
    print(f"Topic:   {topic}")
    print(f"Message: {text}")

    response = make_response(topic, text)

    print(f"[REPLY]  {response}")

    # Small delay so we don't immediately collide with another agent.
    time.sleep(1)

    try:
        post_signed("lobby", response)
    except subprocess.CalledProcessError as e:
        print(f"[SIGN ERROR] {e}")
    except Exception as e:
        print(f"[REPLY ERROR] {e}")


def parse_messages(body):
    """
    Parse lines such as:

    [2731234] 2026-08-26T21:03:12.872062Z <z6Mk…abcd> message
    """

    pattern = re.compile(
        r"^\[(\d+)\]\s+(\S+)\s+<([^>]+)>\s+(.*)$"
    )

    messages = []

    for line in body.splitlines():
        match = pattern.match(line)

        if not match:
            continue

        seq = int(match.group(1))
        timestamp = match.group(2)
        sender = match.group(3)
        text = match.group(4)

        messages.append(
            (seq, timestamp, sender, text)
        )

    return messages


def initialise_cursor():
    """
    If there is no saved cursor, fetch the current lobby and start from
    its newest sequence. This prevents the agent from replying to thousands
    of historical messages on first launch.
    """

    if os.path.exists(CURSOR_FILE):
        return load_cursor()

    print("[INIT] Finding current lobby position...")

    response = session.get(
        LOBBY_URL,
        timeout=30,
    )
    response.raise_for_status()

    messages = parse_messages(response.text)

    if messages:
        newest = max(message[0] for message in messages)
        save_cursor(newest)

        print(f"[INIT] Starting from lobby seq {newest}")
        return newest

    print("[INIT] Lobby appears empty.")
    save_cursor(0)

    return 0


def monitor():
    last_seq = initialise_cursor()

    print()
    print("========================================")
    print("xaud-agent LIVE LOBBY MONITOR")
    print("========================================")
    print(f"DID: {EXPECTED_DID}")
    print(f"Cursor: {last_seq}")
    print("Watching:")
    print("  trading")
    print("  tokenomics")
    print("  Arthur/Auther Hayes")
    print("  airdrops")
    print("  AI agents")
    print("  building")
    print("========================================")
    print()

    while True:
        try:
            url = (
                f"{LOBBY_URL}"
                f"?since={last_seq}"
                f"&wait=10"
            )

            response = session.get(
                url,
                timeout=30,
            )

            if response.status_code == 503:
                print("[SERVER] 503 Service Unavailable — retrying...")
                time.sleep(3)
                continue

            response.raise_for_status()

            messages = parse_messages(response.text)

            if not messages:
                continue

            messages.sort(key=lambda item: item[0])

            for seq, timestamp, sender, text in messages:

                if seq <= last_seq:
                    continue

                # Advance the cursor immediately.
                last_seq = seq
                save_cursor(last_seq)

                print(
                    f"[LOBBY] seq={seq} "
                    f"<{sender}> {text}"
                )

                process_message(
                    seq,
                    timestamp,
                    sender,
                    text,
                )

        except requests.RequestException as e:
            print(f"[NETWORK ERROR] {e}")
            print("Retrying in 5 seconds...")
            time.sleep(5)

        except KeyboardInterrupt:
            print("\nAgent stopped.")
            break

        except Exception as e:
            print(f"[ERROR] {type(e).__name__}: {e}")
            time.sleep(3)


if __name__ == "__main__":
    # Verify the signing identity before joining the lobby.
    print("Checking DID...")

    try:
        did = get_did()
        print(f"DID verified: {did}")
    except Exception as e:
        print(f"DID verification failed: {e}")
        raise SystemExit(1)

    monitor()
