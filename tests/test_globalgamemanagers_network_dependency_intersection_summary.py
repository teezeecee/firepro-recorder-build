"""FACT-0342: static source-only cross-object join regression."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/network_590_dependency_intersection.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0342-original-ggm-network-resource-dependency-intersection.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
manifest=json.loads((R/"canonical/source_manifest.json").read_text())
o=w["source_objects"];j=w["join"]
assert f["fact_id"]=="FACT-0342" and f["status"]=="PROVEN_PACKED_DATA" and f["chain_edges"]==[]
assert w["dataset_id"]=="UNITY_GGM_NETWORK_590_RESOURCE_DEPENDENCY_INTERSECTION_V1"
assert (w["original_file"]["bytes"],w["original_file"]["sha256"])==(5002540,"04cf0c7a5ef858ce68ff5b00b7281ded8fc5b4efe84539d26c21799a4044c22c")
assert next(s for s in manifest["sources"] if s["source_id"]=="GGM-001")["sha256"]==w["original_file"]["sha256"]
assert o["resource_manager"]["sha256"]=="414f1fba01d63bf13a63d82d9b7dbb7fd6223616deb4a57cb3a2ac1f8cbaf9de"
assert o["class149"]["sha256"]=="f4fe8dc74035736ffd35c907e01ef11d46635cec7fb0924aa4f1785b6acc8133"
assert o["resource_manager"]["name_index_records"]==43941 and o["resource_manager"]["dependency_records"]==65218
assert o["class149"]["rows"]==590 and o["class149"]["header_bytes"]+o["class149"]["rows"]*o["class149"]["row_bytes"]==16532
assert (j["both_parent_and_child"],j["parent_only"],j["child_only"],j["neither"])==(561,0,0,29)
assert (j["both_with_resource_name"],j["both_without_resource_name"],j["neither_with_resource_name"],j["neither_without_resource_name"])==(534,27,0,29)
assert j["both_by_file_id"]=={"4":4,"5":557} and j["neither_by_file_id"]=={"4":2,"7":9,"9":12,"10":1,"11":5}
assert sum(j["outgoing_arity_counts"].values())==561
assert sum(int(k)*v for k,v in j["outgoing_arity_counts"].items())==j["total_outgoing_occurrences_for_joined_parents"]==1491
assert j["total_incoming_occurrences_for_joined_references"]==1602
assert j["named_parent_outgoing_occurrences"]==1437 and j["named_reference_incoming_occurrences"]==1538
assert sum(j["both_named_categories"].values())==534
assert len(j["anchors"])==8 and j["anchors"][0]["index"]==0 and j["anchors"][-1]["index"]==589
assert all(a["relation"] in ("both","neither") for a in j["anchors"])
family=[x for x in reg["families"] if x["fact_id"]=="FACT-0342"]
assert len(family)==1 and family[0]["family_id"]==w["dataset_id"] and not family[0]["runtime_eligible"]
assert not reg["runtime_unlocked"]
print("FACT-0342 original globalgamemanagers three-way numeric join source-only: PASS")

