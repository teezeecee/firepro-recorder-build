"""FACT-0328 original Unity area slot source-only regression."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/navmesh_areas_full.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0328-original-unity-navmesh-areas.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
m=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"])==("FACT-0328","PROVEN_PACKED_DATA")
s=next(z for z in m["sources"] if z["source_id"]=="GGM-001")
assert s["canonical_eligible"] and w["original_file"]["sha256"]==s["sha256"]
o=w["object"]
assert (o["class_id"],o["type_index"],o["path_id"],o["absolute_offset"],o["relative_offset"],o["bytes"])==(126,15,16,0x4C51D8,0x4C41D8,360)
a=w["areas"];es=a["entries"]
assert (a["count"],a["count_field_offset"],a["first_row_offset"],a["rows_end_offset"])==(32,0,4,284)
assert len(es)==32 and [e["index"] for e in es]==list(range(32))
assert [(e["name"],e["cost"]) for e in es[:3]]==[("Walkable",1),("Not Walkable",1),("Jump",2)]
assert all(e["name"]=="" and e["cost"]==1 for e in es[3:])
assert es[0]["start_offset"]==4 and es[-1]["end_offset"]==284
assert all(x["end_offset"]==y["start_offset"] for x,y in zip(es,es[1:]))
tail=w["remaining_raw"]
assert (tail["start_offset"],tail["bytes"],tail["literal_at_offset_352"],tail["literal_bytes"])==(284,76,"Humanoid",8)
assert len(o["sha256"])==len(tail["sha256"])==len(a["array_region_sha256"])==64
v=[x for x in reg["families"] if x["fact_id"]=="FACT-0328"]
assert len(v)==1 and v[0]["family_id"]==w["dataset_id"] and v[0]["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False and len({x["family_id"] for x in reg["families"]})==len(reg["families"])
print("UNITY GGM NAVMESH AREAS 32 ORIGINAL SOURCE SLOTS: PASS")
