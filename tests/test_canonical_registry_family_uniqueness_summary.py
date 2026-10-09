#!/usr/bin/env python3
"""Prevent distinct DLL methods silently sharing one canonical registry identity."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
registry=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
families=registry["families"]
keys=[f["family_id"] for f in families]
assert len(keys)==len(set(keys)), "Duplicate family_id in canonical registry"
current=[f for f in families if f["fact_id"]=="FACT-0261"]
previous=[f for f in families if f["fact_id"]=="FACT-0244"]
assert len(current)==len(previous)==1
assert previous[0]["family_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_COUNTER_V1"
assert current[0]["family_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_COUNTER_DURATION_WRITE_REFERENCES_V1"
assert current[0]["family_id"]!=previous[0]["family_id"]
for family in current+previous:
    witness=json.loads((ROOT/family["summary"]).read_text(encoding="utf-8"))
    assert witness["dataset_id"]==family["family_id"], (family["fact_id"],"dataset_id != family_id")
assert (ROOT/"canonical/facts/FACT-0043-set-ai-act-core.json").exists()
assert (ROOT/"canonical/facts/FACT-0261-playercontroller-ai-set-ai-act-counter.json").exists()
print("CANONICAL REGISTRY FAMILY UNIQUENESS: PASS")
