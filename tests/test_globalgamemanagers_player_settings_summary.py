"""FACT-0335 original Unity PlayerSettings source summary and project lock."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/player_settings_546_bytes.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0335-original-unity-player-settings.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
manifest=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"],f["chain_edges"])==("FACT-0335","PROVEN_PACKED_DATA",[])
s=next(x for x in manifest["sources"] if x["source_id"]=="GGM-001")
assert s["canonical_eligible"] and s["sha256"]==w["original_file"]["sha256"]
o=w["object"]
assert (o["class_id"],o["type_index"],o["path_id"],o["relative_offset"],o["absolute_offset"],o["bytes"])==(129,0,1,0,4096,546)
assert o["sha256"]=="29b1dc16893a24b45a5adf174363f8a0f62041ab79a41477bb95dddd789d6773"
segments=w["regions"]
assert len(segments)==10 and segments[0]["start_offset"]==0 and segments[-1]["end_offset"]==546
assert all(a["end_offset"]==b["start_offset"] for a,b in zip(segments,segments[1:]))
assert sum(x["bytes"] for x in segments)==546
assert [(x["offset"],x["value"]) for x in w["strings"]]==[(36,"spikechunsoft"),(56,"FireProWrestlingWorld"),(344,"public.app-category.games"),(484,"1.0")]
assert w["numeric_quad"]["values"]==[1280,720,960,600]
assert w["numeric_quad"]["offset"]==240
e=[x for x in reg["families"] if x["fact_id"]=="FACT-0335"]
assert len(e)==1 and e[0]["family_id"]==w["dataset_id"] and e[0]["runtime_eligible"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert reg["runtime_unlocked"] is False
print("UNITY ORIGINAL PLAYER SETTINGS 546 FULL BYTES SOURCE: PASS")
