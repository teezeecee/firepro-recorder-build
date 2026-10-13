"""FACT-0301: witness, original byte digest and locked registry summary."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_winning_tech_disp_type_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0301-skill-info-manager-parse-winning-tech-disp-type-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];b=bytes.fromhex(m["body_hex"])
assert (f["fact_id"],f["status"])==("FACT-0301","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_WINNING_TECH_DISP_TYPE_SOURCE_V1",["DLL-001"])
assert m["token"]=="0x0600115D" and m["name"]=="Parse_WinningTechDispType"
assert len(b)==m["body_length"]==71 and hashlib.sha256(b).hexdigest()==m["body_sha256"]
assert [tuple((x["start"],x["length"])) for x in w["substring_windows"]]==[(1,1),(0,1)]
assert [x["call_site"] for x in w["substring_windows"]]==[16,43]
assert [x["site"] for x in w["memberrefs"]]==[1,16,26,43,48]
assert [(x["site"],x["target"]) for x in w["branches"]]==[(6,13),(31,38),(56,69),(64,69)]
assert w["exception"]["try_offset"]==40 and w["exception"]["catch_type"]=="0x010000C2"
assert w["literal"]["value"]==" " and w["parent"]["direct_call_sites"]==[262]
assert sum(x["fact_id"]=="FACT-0301" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})
assert reg["runtime_unlocked"] is False and reg["families"][-1]["runtime_eligible"] is False
print("SKILL INFO MANAGER WINNING TECH DISP TYPE SOURCE SUMMARY: PASS")
