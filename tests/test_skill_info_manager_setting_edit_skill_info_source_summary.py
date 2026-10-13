"""FACT-0310: pinned original 93-byte IL, source witnesses and append-safe registry."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_setting_edit_skill_info_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0310-skill-info-manager-setting-edit-skill-info-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];il=bytes.fromhex(m["body_hex"])
assert (f["fact_id"],f["status"])==("FACT-0310","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_SETTING_EDIT_SKILL_INFO_SOURCE_V1",["DLL-001"])
assert (m["token"],m["name"],m["body_length"])==("0x06001154","SettingEditSkillInfo",93)
assert len(il)==93 and hashlib.sha256(il).hexdigest()==m["body_sha256"]
assert [(x["site"],x["target"]) for x in w["branches"]]==[(11,92),(18,76),(87,23)]
assert [(x["token"],x["sites"]) for x in w["fields"]]==[("0x040091C2",[0,23,35,77]),("0x04000EDA",[48]),("0x04000EDB",[61])]
assert [(x["token"],x["sites"]) for x in w["memberrefs"]]==[("0x0A00000F",[6]),("0x0A000754",[55]),("0x0A0006A0",[67])]
assert [(x["token"],x["sites"]) for x in w["methoddef_calls"]]==[("0x06005F6E",[29]),("0x06005F71",[41]),("0x06005F6D",[82])]
assert w["direct_callers"][0]["sites"]==[589,754]
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})>=309
assert sum(x["fact_id"]=="FACT-0310" for x in reg["families"])==1
assert reg["runtime_unlocked"] is False
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0310")["runtime_eligible"] is False
print("SKILL INFO MANAGER SETTING EDIT SKILL INFO SOURCE SUMMARY: PASS")
