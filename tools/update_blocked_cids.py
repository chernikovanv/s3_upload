#!/usr/bin/env python3
"""Refresh the embedded do-not-copy list in s3_upload.py from a clusters CSV.

Usage: python3 tools/update_blocked_cids.py clusters-prod.csv [s3_upload.py]

Rewrites the block between the BEGIN/END BLOCKED CIDS markers. The export is
treated as untrusted input: only the cluster_id column is read, and every value
must match CID before it reaches the script.
"""

import csv
import re
import sys
from pathlib import Path

CID = re.compile(r"[a-z0-9]{16,24}")
PER_LINE = 3
BLOCK = re.compile(r"(# BEGIN BLOCKED CIDS\n).*?(# END BLOCKED CIDS\n)", re.DOTALL)


def read_cids(source):
    with source.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows or "cluster_id" not in rows[0]:
        raise SystemExit(f"{source}: no cluster_id column")
    cids, rejected = set(), []
    for number, row in enumerate(rows, 2):
        value = (row.get("cluster_id") or "").strip()
        if CID.fullmatch(value):
            cids.add(value)
        elif any((row.get(key) or "").strip() for key in row):
            rejected.append(f"line {number}: {value!r}")
    if not cids:
        raise SystemExit(f"{source}: no usable cluster ids")
    for item in rejected[:10]:
        print(f"rejected {item}", file=sys.stderr)
    if len(rejected) > 10:
        print(f"... and {len(rejected) - 10} more rejected", file=sys.stderr)
    return sorted(cids), len(rows)


def main():
    if not 2 <= len(sys.argv) <= 3:
        raise SystemExit(__doc__)
    source = Path(sys.argv[1])
    target = Path(sys.argv[2]) if len(sys.argv) == 3 else \
        Path(__file__).resolve().parent.parent / "s3_upload.py"
    cids, rows = read_cids(source)
    lines = ["    ".join(cids[start:start + PER_LINE])
             for start in range(0, len(cids), PER_LINE)]
    body = 'BLOCKED_CIDS = frozenset("""\n' + "\n".join(lines) + '\n""".split())\n'
    script = target.read_text(encoding="utf-8")
    if not BLOCK.search(script):
        raise SystemExit(f"{target}: BEGIN/END BLOCKED CIDS markers not found")
    updated = BLOCK.sub(lambda m: m.group(1) + body + m.group(2), script, count=1)
    target.write_text(updated, encoding="utf-8")
    print(f"{source}: {rows} rows -> {len(cids)} unique cluster ids -> {target}")


if __name__ == "__main__":
    main()
