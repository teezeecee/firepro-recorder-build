"""FACT-0304: original tiny lookup method IL, caller sites and locked registry."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_skill_count_validity_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0304-skill-info-manager-count-validity-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_SKILL_COUNT_VALIDITY_LOOKUPS_V1",["DLL-001"])
assert (f["fact_id"],f["status"])==("FACT-0304","PROVEN_DLL")
assert [m["token"] for m in w["methods"]]==["0x06001162","0x06001163"]
assert [m["body_length"] for m in w["methods"]]==[12,21]
for m in w["methods"]:
    body=bytes.fromhex(m["body_hex"])
    assert len(body)==m["body_length"] and hashlib.sha256(body).hexdigest()==m["body_sha256"]
assert w["source_field"]["token"]=="0x04000EDA"
assert [r["token"] for r in w["memberrefs"]]==["0x0A000758","0x0A000752"]
assert w["validity_branches"]["conditional_site"]==12
assert w["validity_branches"]["false_target"]==19
assert [c["call_sites"] for c in w["direct_callers"]]==[[91,141,201],[1941]]
assert sum(x["fact_id"]=="FACT-0304" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})>=303
assert reg["runtime_unlocked"] is False
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0304")["runtime_eligible"] is False
print("SKILL INFO MANAGER SKILL COUNT VALIDITY SOURCE SUMMARY: PASS")
