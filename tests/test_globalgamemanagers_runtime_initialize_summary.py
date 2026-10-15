"""FACT-0336 original Unity ClassID300 whole source summary and lock."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/runtime_initialize_164_bytes.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0336-original-unity-runtime-initialize.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
manifest=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"],f["chain_edges"])==("FACT-0336","PROVEN_PACKED_DATA",[])
source=next(s for s in manifest["sources"] if s["source_id"]=="GGM-001")
assert source["canonical_eligible"] and source["sha256"]==w["original_file"]["sha256"]
o=w["object"]
assert (o["class_id"],o["type_index"],o["path_id"],o["relative_offset"],o["absolute_offset"],o["bytes"])==(300,17,20,4998160,0x4C5410,164)
assert o["sha256"]=="5ed10c7654fdd8699015a3f23be23f2514456de934a8614099c3957583a11860"
rows=w["regions"];assert len(rows)==9 and rows[0]["start_offset"]==0 and rows[-1]["end_offset"]==164
assert all(a["end_offset"]==b["start_offset"] for a,b in zip(rows,rows[1:]))
assert sum(s["bytes"] for s in rows)==164
assert [(s["offset"],s["byte_length"],s["value"]) for s in w["strings"]]==[(4,26,"UnityEditor.Advertisements"),(40,26,"UnityEditor.Advertisements"),(84,14,"UnityAdsEditor"),(124,12,"EditorOnLoad")]
assert [(x["name"],x["u32_values"]) for x in rows if "u32_values" in x]==[
("leading_numeric",[1]),("numeric_after_name_0",[1]),("numeric_after_name_1",[1,0,0]),("numeric_after_name_2",[1,0,0,1,0]),("trailing_numeric",[0,1,0,0,0,0])]
entries=[x for x in reg["families"] if x["fact_id"]=="FACT-0336"]
assert len(entries)==1 and entries[0]["family_id"]==w["dataset_id"] and entries[0]["runtime_eligible"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert reg["runtime_unlocked"] is False
print("UNITY ORIGINAL RUNTIME INITIALIZE ON LOAD 164-BYTE SOURCE: PASS")
