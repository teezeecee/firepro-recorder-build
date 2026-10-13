"""FACT-0308: original IL and append-safe registry proof."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_add_edit_skill_info_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0308-skill-info-manager-add-edit-skill-info-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];body=bytes.fromhex(m["body_hex"])
assert (f["fact_id"],f["status"])==("FACT-0308","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_ADD_EDIT_SKILL_INFO_SOURCE_V1",["DLL-001"])
assert (m["token"],m["name"],m["code_bytes"])==("0x06001155","AddEditSkillInfo",26)
assert len(body)==26 and hashlib.sha256(body).hexdigest()==m["code_sha256"]
assert [f["token"] for f in w["fields"]]==["0x04000EDA","0x04000EDB"]
assert [(r["token"],r["site"]) for r in w["memberrefs"]]==[("0x0A000754",8),("0x0A0006A0",20)]
assert body[6:8]==bytes([4,3]) and body[19]==4 and body[-1]==0x2a
assert [c["sites"] for c in w["direct_callers"]]==[[530],[74],[338]]
assert sum(x["fact_id"]=="FACT-0308" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})>=307
assert reg["runtime_unlocked"] is False
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0308")["runtime_eligible"] is False
print("SKILL INFO MANAGER ADD EDIT SKILL INFO SOURCE SUMMARY: PASS")
