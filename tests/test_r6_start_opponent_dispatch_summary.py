#!/usr/bin/env python3
import base64
import hashlib
import json
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "canonical" / "witnesses" / "CAP-R6-001"
summary = json.loads((BASE / "start_opponent_dispatch.summary.json").read_text(encoding="utf-8"))
meta = summary["witness_artifact"]
artifact_path = BASE / meta["path"]
artifact = artifact_path.read_bytes()

assert hashlib.sha256(artifact).hexdigest() == meta["sha256"]
decoded = zlib.decompress(base64.b64decode(artifact))
assert hashlib.sha256(decoded).hexdigest() == meta["decoded_binary_sha256"]
assert decoded[:5] == b"R6SO1"

def read_varint(buf, pos):
    value = 0
    shift = 0
    while True:
        assert pos < len(buf)
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7
        assert shift <= 63

pos = 5
count, pos = read_varint(decoded, pos)
assert count == meta["record_count"] == 847

parent_lines = []
parent = 0
for _ in range(count):
    delta, pos = read_varint(decoded, pos)
    parent += delta
    post_delta, pos = read_varint(decoded, pos)
    child_delta, pos = read_varint(decoded, pos)
    assert delta > 0
    assert post_delta > 0
    assert child_delta > 0
    parent_lines.append(parent)

assert pos == len(decoded)
assert parent_lines == sorted(parent_lines)
assert len(parent_lines) == len(set(parent_lines)) == 847

obs = summary["r6_observation"]
assert obs["start_opponent_anm_calls_pre"] == 847
assert obs["start_opponent_anm_calls_post"] == 847
assert obs["paired_parent_calls"] == 847
assert obs["exactly_one_nested_request_per_parent"] == 847
assert obs["nested_request_counts"] == {
    "FormAnimator.ReqBasicAnm": 585,
    "FormAnimator.ReqSlotAnm": 262,
    "FormAnimator.ReqSerialAnm": 0,
    "FormAnimator.ReqSkillAnm": 0,
}
assert obs["first_recorded_arg_equals_parent_target_equals_child_owner_slot"] == 847
assert obs["slot_branch_parent_child_resolved_skill_id_equal"] == 262
assert obs["slot_branch_child_resolved_skill_source"] == {"StartOpponentAnm.host_skill": 262}

dll = summary["dll_method"]
assert dll["token"] == "0x06004E76"
assert dll["rva"] == "0x002DABA8"
assert dll["code_size"] == 905
assert dll["code_sha256"] == "4b390293560fe3a02b12845d80419fe4d8747c637a3c94221cf2dac051ffb2cb"
assert [x["call_token"] for x in dll["request_dispatch"]] == [
    "0x06004E6D", "0x06004E6E", "0x06004E6F", "0x06004E70"
]

print("R6 START OPPONENT DISPATCH SUMMARY: PASS")
