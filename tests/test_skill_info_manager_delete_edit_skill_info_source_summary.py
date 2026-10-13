"""FACT-0309: raw original 94-byte IL, caller witnesses, append-safe registry."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_delete_edit_skill_info_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0309-skill-info-manager-delete-edit-skill-info-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];il=bytes.fromhex(m["body_hex"])
assert (f["fact_id"],f["status"])==("FACT-0309","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_DELETE_EDIT_SKILL_INFO_SOURCE_V1",["DLL-001"])
assert (m["token"],m["name"],m["body_length"])==("0x06001156","DeleteEditSkillInfo",94)
assert len(il)==94 and hashlib.sha256(il).hexdigest()==m["body_sha256"]
assert [(x["site"],x["target"]) for x in w["branches"]]==[(2,46),(20,42),(37,63),(58,7),(75,93)]
assert [(x["token"],x["sites"]) for x in w["fields"]]==[("0x04000EDB",[8,26,48]),("0x04000EDA",[64,81])]
assert [(x["token"],x["sites"]) for x in w["memberrefs"]]==[("0x0A000699",[14]),("0x0A000756",[32]),("0x0A00069B",[53]),("0x0A000752",[70]),("0x0A000757",[87])]
assert [x["sites"] for x in w["direct_callers"]]==[[145],[325],[21],[160],[90]]
assert sum(x["fact_id"]=="FACT-0309" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})>=308
assert reg["runtime_unlocked"] is False
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0309")["runtime_eligible"] is False
print("SKILL INFO MANAGER DELETE EDIT SKILL INFO SOURCE SUMMARY: PASS")
