"""FACT-0299 static source witness, full bytes and locked registry."""
import hashlib,json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_primary_skill_strength_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((R/"canonical/facts/FACT-0299-skill-info-manager-parse-primary-skill-strength-source.json").read_text(encoding="utf-8"))
reg=json.loads((R/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];il=bytes.fromhex(m["il_hex"])
assert (f["fact_id"],f["status"])==("FACT-0299","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_PRIMARY_SKILL_STRENGTH_SOURCE_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["signature"])==("0x0600115C",69,"000111a9940e")
assert len(il)==69 and hashlib.sha256(il).hexdigest()==m["code_sha256"]
assert [(x["literal"],x["return_ordinal"],x["branch_site"],x["false_target"]) for x in w["literal_cases"]]==[("S",0,24,31),("M",1,42,49),("L",2,60,67)]
assert [x["call_sites"] for x in w["memberrefs"]]==[[1],[19,37,55]]
assert w["empty_check"]["return_site"]==11 and w["default_return"]["site"]==67
assert w["parent"]["direct_call_sites"]==[210]
assert m["has_exception_section"] is False
assert sum(x["fact_id"]=="FACT-0299" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})
assert reg["runtime_unlocked"] is False and reg["families"][-1]["runtime_eligible"] is False
print("SKILL INFO MANAGER PRIMARY SKILL STRENGTH SOURCE SUMMARY: PASS")
