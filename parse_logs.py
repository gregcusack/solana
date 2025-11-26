#!/usr/bin/env python3
import sys

# We’ll detect the start of a snapshot by this header content
HEADER_NEEDLES = ("IP Address", "Node identifier")
NODES_PREFIX = "Nodes:"

BASE58 = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

def is_pubkey(s: str) -> bool:
    s = s.strip()
    # Solana pubkeys: 32 bytes, typically 43–44 base58 chars
    return len(s) in (43, 44) and all(ch in BASE58 for ch in s)

def extract_ip(col0: str) -> str:
    """
    Extract the IP from the first column, e.g.:
        "91.242.214.149  me"      -> "91.242.214.149"
        "162.55.135.231    "      -> "162.55.135.231"
    We'll just take the first whitespace-separated token.
    """
    col0 = col0.strip()
    if not col0:
        return ""
    return col0.split()[0]

def parse_snapshots(path: str):
    """
    Returns: list of snapshots.
    Each snapshot is a dict: { pubkey: ip }
    """
    snapshots = []
    current = {}  # pubkey -> ip
    in_snapshot = False

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.rstrip("\n")

            # Start of a new snapshot = header line containing both needles
            if all(needle in line for needle in HEADER_NEEDLES):
                if in_snapshot and current:
                    snapshots.append(current)
                    current = {}
                in_snapshot = True
                continue

            if not in_snapshot:
                continue

            # End of snapshot = line starting with "Nodes:"
            if line.lstrip().startswith(NODES_PREFIX):
                if current:
                    snapshots.append(current)
                    current = {}
                in_snapshot = False
                continue

            stripped = line.strip()
            if not stripped:
                continue

            # Skip separator rows like "-----+------+---"
            if set(stripped) <= set("-+| "):
                continue

            if "|" not in line:
                continue

            cols = line.split("|")
            if len(cols) < 3:
                continue

            # Column 0: IP / "me" tag, etc.
            ip = extract_ip(cols[0])
            # Column 2: pubkey
            candidate = cols[2].strip()

            if is_pubkey(candidate):
                # Only set the IP the first time we see this pubkey in a snapshot
                current.setdefault(candidate, ip)

    # In case file ends mid-snapshot without a trailing "Nodes:" line
    if in_snapshot and current:
        snapshots.append(current)

    return snapshots

def main(path: str):
    snapshots = parse_snapshots(path)

    if len(snapshots) < 2:
        print(f"Found {len(snapshots)} snapshot(s); need at least two in {path}.", file=sys.stderr)
        sys.exit(1)

    first = snapshots[0]   # dict: pubkey -> ip
    last  = snapshots[-1]  # dict: pubkey -> ip

    first_set = set(first.keys())
    last_set  = set(last.keys())

    disappeared = sorted(first_set - last_set)

    # Print disappeared pubkeys + IP (from first snapshot) to stdout
    # Format: "<pubkey> <ip>"
    for pk in disappeared:
        ip = first.get(pk, "")
        print(f"{pk} {ip}")

    # Summary to stderr
    print(
        f"# snapshots={len(snapshots)}, "
        f"initial={len(first_set)}, final={len(last_set)}, disappeared={len(disappeared)}",
        file=sys.stderr,
    )

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} log1.log", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
