#!/usr/bin/env python3
import base64
import hashlib
import json
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "canonical" / "witnesses" / "CAP-R6-001"
summary = json.loads((BASE / "tick_state_edges.summary.json").read_text(encoding="utf-8"))
index_path = BASE / "tick_state_edges.index.json.zlib.b64"
artifact = index_path.read_bytes()
got_sha = hashlib.sha256(artifact).hexdigest()
assert got_sha == summary["index_file"]["sha256"], (got_sha, summary["index_file"]["sha256"])
decoded = zlib.decompress(base64.b64decode(artifact))
decoded_sha = hashlib.sha256(decoded).hexdigest()
assert decoded_sha == summary["index_file"]["decoded_json_sha256"], (decoded_sha, summary["index_file"]["decoded_json_sha256"])
index = json.loads(decoded.decode("utf-8"))
assert index["dataset_id"] == summary["dataset_id"] == "R6_TICK_STATE_EDGES_V1"
assert index["source_id"] == summary["source_id"] == "CAP-R6-001"
assert len(index["edges"]) == summary["distinct_state_edge_count"] == 105
assert sum(e["count"] for e in index["edges"]) == summary["index_file"]["record_count"] == 5977
assert sum(e["count"] for e in index["edges"]) == sum(len(e["occurrences"]) for e in index["edges"])
assert sum(x["count"] for x in summary["player_transition_counts"]) == 5977

fields = index["occurrence_fields"]
assert fields == ["player_slot","before_line","after_line"]
for edge in index["edges"]:
    assert edge["from_State"] != edge["to_State"]
    assert edge["count"] == len(edge["occurrences"])
    for occ in edge["occurrences"]:
        assert len(occ) == len(fields)
        slot, before_line, after_line = occ
        assert 0 <= slot <= 7
        assert before_line < after_line

print("R6 STATE EDGE INDEX: PASS")
