#!/usr/bin/env python3
import base64
import hashlib
import json
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "canonical" / "witnesses" / "CAP-R6-001"
summary = json.loads((BASE / "tick_state_edges.summary.json").read_text(encoding="utf-8"))
meta = summary["index_file"]

chunks = []
for part in meta["parts"]:
    raw = (BASE / part["path"]).read_text(encoding="ascii").strip().encode("ascii")
    assert len(raw) == part["trimmed_length"], (part["path"], len(raw), part["trimmed_length"])
    got_part_sha = hashlib.sha256(raw).hexdigest()
    assert got_part_sha == part["trimmed_sha256"], (part["path"], got_part_sha, part["trimmed_sha256"])
    chunks.append(raw)

artifact = b"".join(chunks) + b"\n"
got_artifact_sha = hashlib.sha256(artifact).hexdigest()
assert got_artifact_sha == meta["reconstructed_sha256"], (got_artifact_sha, meta["reconstructed_sha256"])
decoded = zlib.decompress(base64.b64decode(artifact))
decoded_sha = hashlib.sha256(decoded).hexdigest()
assert decoded_sha == meta["decoded_json_sha256"], (decoded_sha, meta["decoded_json_sha256"])
index = json.loads(decoded.decode("utf-8"))
assert index["dataset_id"] == summary["dataset_id"] == "R6_TICK_STATE_EDGES_V1"
assert index["source_id"] == summary["source_id"] == "CAP-R6-001"
assert len(index["edges"]) == summary["distinct_state_edge_count"] == 105
assert sum(e["count"] for e in index["edges"]) == meta["record_count"] == 5977
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
