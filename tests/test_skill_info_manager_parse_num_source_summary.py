"""FACT-0297: source-only original Parse_Num static witness test."""
import json,hashlib
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_num_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((R/"canonical/facts/FACT-0297-skill-info-manager-parse-num-source.json").read_text(encoding="utf-8"))
reg=json.loads((R/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];b=bytes.fromhex(m["il_hex"])
assert (f["fact_id"],f["status"])==("FACT-0297","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_NUM_SOURCE_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["rva"])==("0x06001158",37,"0x00069604")
assert len(b)==37 and hashlib.sha256(b).hexdigest()==m["code_sha256"]
assert m["signature"]=="0002080e0e"
assert w["members"][0]["name"]=="IsNullOrEmpty" and w["members"][1]["name"]=="Parse"
assert [(x["site"],x["target"]) for x in w["branch_flow"]]==[(6,13),(22,35),(30,35)]
assert w["exception_section"]["catch_type_token"]=="0x010000C2"
assert w["exception_section"]["source_hex"]=="0110000000000d000e1b0008c2000001"
assert len(w["parent"]["call_sites"])==18 and len(set(w["parent"]["call_sites"]))==18
assert w["source_semantics"]["only_ldarg_0"] is True
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})
assert sum(x["fact_id"]=="FACT-0297" for x in reg["families"])==1
assert reg["runtime_unlocked"] is False and reg["families"][-1]["runtime_eligible"] is False
print("SKILL INFO MANAGER PARSE NUM SOURCE SUMMARY: PASS")
