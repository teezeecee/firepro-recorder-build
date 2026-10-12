"""FACT-0293 SkillInfoManager Awake and four original resource loader wrappers."""
import json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_awake_four_resource_wrappers.summary.json").read_text())
fact=json.loads((ROOT/"canonical/facts/FACT-0293-skill-info-manager-awake-four-resource-wrappers.json").read_text())
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text())
d=w["dll"];ms=d["methods"]
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_AWAKE_AND_FOUR_RESOURCE_WRAPPERS_V1",["DLL-001"])
assert (fact["fact_id"],fact["status"])==("FACT-0293","PROVEN_DLL")
assert [m["code_bytes"] for m in ms]==[64,59,59,59,59]
assert sum(m["code_bytes"] for m in ms)==300
assert all(hashlib.sha256(bytes.fromhex(m["il_hex"])).hexdigest()==m["code_sha256"] for m in ms)
assert [m["resource_name"] for m in ms[1:]]==["DataBase/SkillParam","DataBase/SkillInfo","DataBase/StorySkillUnlock","DataBase/SkillParam_Reversal"]
assert (len(d["raw_fielddefs"]),len(d["raw_memberrefs"]),len(d["internal_parsers"]),len(d["awake_method_calls"]))==(4,8,4,4)
assert len({x["resource_name"] for x in ms[1:]})==4 and len({x["internal_parser_token"] for x in ms[1:]})==4
assert sum(x["fact_id"]=="FACT-0293" for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
print("SKILL INFO MANAGER AWAKE FOUR RESOURCE WRAPPERS SUMMARY: PASS")
