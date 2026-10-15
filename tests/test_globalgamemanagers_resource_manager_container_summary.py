"""FACT-0338: complete original ResourceManager 43,941-name/PPtr table witness invariants."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/resource_manager_container_43941.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0338-original-unity-resource-manager-container.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
manifest=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"],f["chain_edges"])==("FACT-0338","PROVEN_PACKED_DATA",[])
src=next(x for x in manifest["sources"] if x["source_id"]=="GGM-001")
assert src["canonical_eligible"] and src["sha256"]==w["original_file"]["sha256"]
o=w["object"]
assert (o["class_id"],o["type_index"],o["path_id"],o["relative_offset"],o["absolute_offset"],o["bytes"])==(147,12,13,118728,0x1DFC8,4862328)
assert o["sha256"]=="414f1fba01d63bf13a63d82d9b7dbb7fd6223616deb4a57cb3a2ac1f8cbaf9de"
c=w["container"];tail=w["unparsed_tail"]
assert (c["count"],c["first_row_offset"],c["end_offset"])==(43941,4,2138488)
assert c["raw_count_and_rows_sha256"]=="d4ee5f6e796f04cccc5c1b381df3f08e216e66ea7e1c85e0da034d3c5cde8394"
assert (tail["start_offset"],tail["end_offset"],tail["bytes"],tail["first_u32_raw_value"])==(2138488,4862328,2723840,65218)
assert tail["sha256"]=="64d856b31b479f81612b2f833ac25ac2cfaf6e84cf02bedcbe3adf06b13535fc"
assert c["file_id_counts"]=={"4":11,"5":43930}
assert c["file_id_external_paths"]=={"4":"sharedassets0.assets","5":"resources.assets"}
assert c["distinct_names"]==24973 and c["distinct_numeric_reference_pairs"]==43941
assert len(c["category_counts"])==26 and sum(c["category_counts"].values())==43941
assert c["category_counts"]["partstex"]==35365
assert c["category_counts"]["wrestleranimation"]==445
assert c["category_counts"]["weapon"]==321
assert c["category_counts"]["sound"]==2996
assert c["category_counts"]["stage"]==503
assert [(x["name"],x["file_id"],x["path_id"]) for x in c["anchors"] if x["name"]=="fprwaza"]==[("fprwaza",5,22804)]
assert len(c["anchors"])==14 and len({x["index"] for x in c["anchors"]})==14
assert c["first_rows"][0]==["buttonguide/g00_000",5,4962]
assert c["last_rows"][-1]==["wrestleranimation/fpw_6261",5,21624]
e=[x for x in reg["families"] if x["fact_id"]=="FACT-0338"]
assert len(e)==1 and e[0]["family_id"]==w["dataset_id"] and e[0]["runtime_eligible"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert reg["runtime_unlocked"] is False
print("UNITY ORIGINAL RESOURCE MANAGER 43941 SOURCE NAME/PPTR RECORDS: PASS")
