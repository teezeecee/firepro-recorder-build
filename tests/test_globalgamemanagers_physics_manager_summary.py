"""FACT-0329 original Unity PhysicsManager 180 byte source metadata regression."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/physics_manager_180_bytes.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0329-original-unity-physics-manager.json").read_text())
r=json.loads((R/"canonical/transition_registry.json").read_text())
m=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"])==("FACT-0329","PROVEN_PACKED_DATA")
src=next(x for x in m["sources"] if x["source_id"]=="GGM-001")
assert src["canonical_eligible"] and w["original_file"]["sha256"]==src["sha256"]
o=w["object"]
assert (o["class_id"],o["class_name"],o["type_index"],o["path_id"],o["relative_offset"],o["absolute_offset"],o["bytes"])==(55,"PhysicsManager",9,10,62760,0x10528,180)
p=w["prefix"];assert (p["offset"],p["bytes"])==(0,52) and len(p["hex"])==104
g=w["gravity"];assert (g["offset"],g["bytes"],g["components_f32_round6"])==(0,12,[0,-9.81,0])
a=w["other_configuration"];assert (a["offset"],a["bytes"],a["hex"])==(12,40,p["hex"][24:])
mtrx=w["layer_collision_matrix"]
assert (mtrx["offset"],mtrx["bytes"],mtrx["rows"],mtrx["per_row_bytes"],mtrx["word_unsigned"])==(52,128,32,4,4294967295)
assert len(mtrx["entries"])==32
assert all((e["layer"],e["offset"],e["unsigned_le"],e["hex"])==(i,52+i*4,4294967295,"ffffffff") for i,e in enumerate(mtrx["entries"]))
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
ents=[x for x in r["families"] if x["fact_id"]=="FACT-0329"]
assert len(ents)==1 and ents[0]["family_id"]==w["dataset_id"] and ents[0]["runtime_eligible"] is False
assert r["runtime_unlocked"] is False
print("GGM UNITY PHYSICS MANAGER 180B SOURCE: PASS")
