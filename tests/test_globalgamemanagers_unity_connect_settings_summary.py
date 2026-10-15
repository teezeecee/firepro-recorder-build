"""FACT-0337 exact original UnityConnectSettings source summary/lock invariants."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/unity_connect_settings_116_bytes.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0337-original-unity-connect-settings.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
manifest=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"],f["chain_edges"])==("FACT-0337","PROVEN_PACKED_DATA",[])
source=next(s for s in manifest["sources"] if s["source_id"]=="GGM-001")
assert source["canonical_eligible"] and source["sha256"]==w["original_file"]["sha256"]
o=w["object"]
assert (o["class_id"],o["type_index"],o["path_id"],o["relative_offset"],o["absolute_offset"],o["bytes"])==(310,19,23,4998328,0x4C54B8,116)
assert o["sha256"]=="09472756af261fbf6ec963005e7ecf38abf921e1c4508aa334c28da595881ab7"
regions=w["regions"]
assert len(regions)==4 and regions[0]["start_offset"]==0 and regions[-1]["end_offset"]==116
assert all(a["end_offset"]==b["start_offset"] for a,b in zip(regions,regions[1:]))
assert sum(x["bytes"] for x in regions)==116
assert w["embedded_url"]=={"object_offset":16,"length_prefix_u32":56,"bytes_start":20,"bytes_end":76,"value":"https://perf-events.cloud.unity3d.com/api/events/crashes"}
assert [x["unlabelled_u32"] for x in regions if "unlabelled_u32" in x]==[[0,0,0,0],[0,0,256,0,0],[256,4294967295,0,0,0]]
e=[x for x in reg["families"] if x["fact_id"]=="FACT-0337"]
assert len(e)==1 and e[0]["family_id"]==w["dataset_id"] and e[0]["runtime_eligible"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert reg["runtime_unlocked"] is False
print("UNITY ORIGINAL UNITYCONNECTSETTINGS COMPLETE 116 BYTE SOURCE: PASS")
