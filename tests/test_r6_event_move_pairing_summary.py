#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
s = json.loads((ROOT / "canonical" / "witnesses" / "CAP-R6-001" / "event_move_pairing.summary.json").read_text(encoding="utf-8"))
r = s["result"]

assert s["dataset_id"] == "R6_EVENT_MOVE_PAIRING_V1"
assert s["source_id"] == "CAP-R6-001"
assert s["promotion_scope"] == "RAW_OBSERVATION_ONLY"
assert s["semantic_claims"] == []
assert len(s["shared_fields"]) == 19
assert s["members"]["event_trace"]["data_rows"] == 840372
assert s["members"]["move_trace"]["data_rows"] == 127016
assert r["event_rows_with_type_FormAnimator"] == 127016
assert r["move_rows"] == 127016
assert r["matched_pairs"] == 127016
assert r["missing_partner_rows"] == 0
assert r["shared_field_mismatch_rows"] == 0
assert r["seq_delta_counts"] == {"1": 127016}
assert sum(r["method_counts"].values()) == 127016
assert len(r["method_counts"]) == 8
assert r["pairing_digest_sha256"] == "3d5524f74d69c87062b6155bdf65bd88c7d23854ca8db5ce8f4d0dc92169c6e5"
assert r["first_pair"]["event_seq"] + 1 == r["first_pair"]["move_seq"]
assert r["last_pair"]["event_seq"] + 1 == r["last_pair"]["move_seq"]

print("R6 EVENT/MOVE PAIRING SUMMARY: PASS")
