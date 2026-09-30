#!/usr/bin/env python3
import base64
import hashlib
import json
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "canonical" / "witnesses" / "CAP-R6-001"
SUMMARY_PATH = BASE / "tick_state_edges.summary.json"
summary = json.loads(SUMMARY_PATH.read_text(encoding="utf-8"))
index_path = BASE / summary["index_file"]["path"]
artifact = index_path.read_bytes()

got_sha = hashlib.sha256(artifact).hexdigest()
assert got_sha == summary["index_file"]["sha256"], (got_sha, summary["index_file"]["sha256"])

decoded = zlib.decompress(base64.b64decode(artifact))
decoded_sha = hashlib.sha256(decoded).hexdigest()
assert decoded_sha == summary["index_file"]["decoded_binary_sha256"], (
    decoded_sha,
    summary["index_file"]["decoded_binary_sha256"],
)

assert decoded[:5] == b"R6SA1"

def get_varint(buf, pos):
    value = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise AssertionError("truncated varint")
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7
        if shift > 63:
            raise AssertionError("oversized varint")

pos = 5
count, pos = get_varint(decoded, pos)
lines = []
line = 0
for _ in range(count):
    delta, pos = get_varint(decoded, pos)
    line += delta
    lines.append(line)

assert pos == len(decoded)
assert count == summary["index_file"]["record_count"] == 5977
assert len(lines) == len(set(lines)) == 5977
assert lines == sorted(lines)
assert lines[0] >= 2
assert lines[-1] <= summary["source_member"]["data_rows"] + 1
assert summary["distinct_state_edge_count"] == len(summary["edge_counts"]) == 105
assert sum(x["count"] for x in summary["edge_counts"]) == 5977
assert sum(x["count"] for x in summary["player_transition_counts"]) == 5977
print("R6 STATE EDGE INDEX: PASS")
