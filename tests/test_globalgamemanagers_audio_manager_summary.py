"""FACT-0327 raw original audio source witness static regression."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/audio_manager_40_bytes.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0327-original-unity-audio-manager.json").read_text())
m=json.loads((R/"canonical/source_manifest.json").read_text())
r=json.loads((R/"canonical/transition_registry.json").read_text())
assert (f["fact_id"],f["status"])==("FACT-0327","PROVEN_PACKED_DATA")
s=next(z for z in m["sources"] if z["source_id"]=="GGM-001")
assert s["canonical_eligible"] and s["sha256"]==w["original_file"]["sha256"]
o=w["object"]
assert (o["class_id"],o["type_index"],o["path_id"],o["relative_offset"],o["absolute_offset"],o["bytes"])==(11,3,4,32896,0x9080,40)
assert len(o["hex"])==80 and len(o["sha256"])==64
assert [x["offset"] for x in w["scalar_prefix"]]==list(range(0,32,4))
assert [x["struct_type"] for x in w["scalar_prefix"]]==["f"]*3+["i"]*5
assert [x["value"] for x in w["scalar_prefix"]]==[1,1,1,2,0,0,512,32]
t=w["unnamed_tail"];assert (t["offset"],t["bytes"],t["hex"],t["as_raw_uint32"])==(32,8,"0000000000010000",[0,256])
assert o["hex"][64:]==t["hex"]
v=[x for x in r["families"] if x["fact_id"]=="FACT-0327"]
assert len(v)==1 and v[0]["family_id"]==w["dataset_id"] and v[0]["runtime_eligible"] is False
assert r["runtime_unlocked"] is False and len({x["family_id"] for x in r["families"]})==len(r["families"])
print("GGM AUDIOMANAGER ORIGINAL FORTY BYTES: PASS")
