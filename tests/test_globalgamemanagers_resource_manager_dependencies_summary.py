"""FACT-0339 original ResourceManager 65,218 dependency record summary checks.

CI never needs user-owned game binary; user can run the raw source verifier separately.
"""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/resource_manager_dependency_65218.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0339-original-resource-manager-dependency-references.json").read_text())
r=json.loads((R/"canonical/transition_registry.json").read_text())
m=json.loads((R/"canonical/source_manifest.json").read_text())
src=next(x for x in m["sources"] if x["source_id"]=="GGM-001")
assert src["canonical_eligible"] and src["sha256"]==w["original_file"]["sha256"]
assert f["fact_id"]=="FACT-0339" and f["status"]=="PROVEN_PACKED_DATA" and f["chain_edges"]==[]
d=w["dependent_records"];o=w["object"];pre=w["preceding_container"]
assert (o["class_id"],o["type_index"],o["path_id"],o["absolute_offset"],o["bytes"])==(147,12,13,122824,4862328)
assert o["sha256"]=="414f1fba01d63bf13a63d82d9b7dbb7fd6223616deb4a57cb3a2ac1f8cbaf9de"
assert pre["end"]==d["start"]==2138488 and d["end"]==o["bytes"]==4862328
assert d["bytes"]==2723840 and d["sha256"]=="64d856b31b479f81612b2f833ac25ac2cfaf6e84cf02bedcbe3adf06b13535fc"
assert d["record_count"]==65218 and d["total_dependency_references"]==140029
assert 4+16*d["record_count"]+12*d["total_dependency_references"]==d["bytes"]
assert d["parsed_to_end_offset"]==d["bytes"]
assert sum(d["parent_file_id_counts"].values())==65218
assert sum(d["dependency_file_id_counts"].values())==140029
assert d["parent_file_id_counts"]=={"1":2,"2":2,"3":1,"4":193,"5":65020}
assert d["dependency_file_id_counts"]=={"1":11678,"2":25,"3":10,"4":5839,"5":122477}
assert d["unique_parent_pairs"]==65218 and d["unique_dependency_pairs"]==67564
assert d["resource_index_parent_matches"]==19731 and d["resource_index_dependency_occurrence_matches"]==22107
assert len(d["anchors"])==11 and d["anchors"][0]["parent"]==[1,4]
assert d["anchors"][-1]["index"]==65217 and d["anchors"][-1]["parent"]==[5,80800]
assert len([x for x in r["families"] if x["fact_id"]=="FACT-0339"])==1
assert next(x for x in r["families"] if x["fact_id"]=="FACT-0339")["family_id"]==w["dataset_id"]
assert not r["runtime_unlocked"]
print("UNITY ORIGINAL RESOURCE MANAGER 65218 DEPENDENCY SOURCE RECORDS: PASS")
