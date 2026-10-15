"""FACT-0331 original TagManager witness and registry invariants."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/tag_manager_full.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0331-original-unity-tag-manager.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
manifest=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"])==("FACT-0331","PROVEN_PACKED_DATA")
source=next(s for s in manifest["sources"] if s["source_id"]=="GGM-001")
assert source["canonical_eligible"] and source["sha256"]==w["original_file"]["sha256"]
o=w["object"]
assert (o["class_id"],o["type_index"],o["path_id"],o["absolute_offset"],o["relative_offset"],o["bytes"])==(78,2,3,0x8CD8,31960,932)
for key,count,start,end in (("tags",18,0,348),("layers",32,348,864),("sorting_layers",4,864,932)):
    t=w[key];rows=t["entries"]
    assert (t["count"],t["count_offset"],t["first_row_offset"],t["end_offset"])==(count,start,start+4,end)
    assert len(rows)==count and [x["index"] for x in rows]==list(range(count))
    assert rows[0]["start_offset"]==start+4 and rows[-1]["end_offset"]==end
    assert all(a["end_offset"]==b["start_offset"] for a,b in zip(rows,rows[1:]))
names=[x["name"] for x in w["layers"]["entries"]]
assert names[10:22]==["StageWall","StageWall_Player","Ring","Ring_Player","BackRope","BackRope_Player","SideCorner","SideCorner_Player","FrontRope","FrontRope_Player","FrontIronPillar","FrontIronPillar_Player"]
assert names[27]=="FrontCage_Player"
sort=w["sorting_layers"]["entries"]
assert [s["name"] for s in sort]==["Player","Default","Stage","Dialog"]
assert [s["unique_id"] for s in sort]==[4060038209,0,1186669689,4237908709]
assert w["related_facts"]==["FACT-0329","FACT-0330"]
e=[x for x in reg["families"] if x["fact_id"]=="FACT-0331"]
assert len(e)==1 and e[0]["family_id"]==w["dataset_id"] and e[0]["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
print("UNITY TAG MANAGER ORIGINAL 18 TAGS 32 LAYERS 4 SORTING LAYERS: PASS")
