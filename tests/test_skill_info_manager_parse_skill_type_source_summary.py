"""FACT-0298: source-only original Parse_SkillType summary."""
import json,hashlib
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_skill_type_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((R/"canonical/facts/FACT-0298-skill-info-manager-parse-skill-type-source.json").read_text(encoding="utf-8"))
reg=json.loads((R/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];b=bytes.fromhex(m["il_hex"])
assert (f["fact_id"],f["status"])==("FACT-0298","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_SKILL_TYPE_SOURCE_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["rva"])==("0x0600115A",71,"0x0006966C")
assert len(b)==71 and hashlib.sha256(b).hexdigest()==m["code_sha256"]
assert m["signature"]=="000111a9880e" and w["literal"]["text"]==" "
assert [x["site"] for x in w["calls"]]==[1,16,26,43,48]
assert [(x["site"],x["target"]) for x in w["branches"]]==[(6,13),(31,38),(56,69),(64,69)]
assert w["exception_section"]["catch_type_token"]=="0x010000C2"
assert w["exception_section"]["try_offset"]==40 and 16<40
assert w["parent"]["direct_call_sites"]==[170]
assert sum(x["fact_id"]=="FACT-0298" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})
assert reg["runtime_unlocked"] is False and reg["families"][-1]["runtime_eligible"] is False
print("SKILL INFO MANAGER PARSE SKILL TYPE SOURCE SUMMARY: PASS")
