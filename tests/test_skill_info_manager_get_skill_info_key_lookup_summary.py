"""FACT-0289 source-only SkillInfoManager GetSkillInfo key lookup witness coverage."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_get_skill_info_key_lookup.summary.json").read_text())
f=json.loads((ROOT/"canonical/facts/FACT-0289-skill-info-manager-get-skill-info-key-lookup.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
d=w["dll"];m=d["method"]
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_GET_SKILL_INFO_KEY_LOOKUP_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x06001164",32,"20b9e57db76492a26682a8438d6b177137717b54048168d56fa33ab8505032bd")
assert hashlib.sha256(bytes.fromhex(m["il_hex"])).hexdigest()==m["code_sha256"]
assert [len(bytes.fromhex(x["il_hex"])) for x in m["segments"]]==[12,7,13]
assert (d["field"]["token"],d["field"]["name"])==("0x04000EDA","skillInfoList")
assert [(k,x["name"],x["callvirt_il"]) for k,x in d["memberrefs"].items()]==[("0x0A000752","ContainsKey","0x0007"),("0x0A000753","get_Item","0x001A")]
assert (d["branch"]["target_il"],d["branch"]["not_found_source_bytes"])==("0x0013","142a")
assert d["parent_call"]["call_hex"]=="6f64110006"
assert f["fact_id"]=="FACT-0289" and f["status"]=="PROVEN_DLL"
assert sum(x["fact_id"]=="FACT-0289" for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
print("SKILL INFO MANAGER GET SKILL INFO KEY LOOKUP SUMMARY: PASS")
