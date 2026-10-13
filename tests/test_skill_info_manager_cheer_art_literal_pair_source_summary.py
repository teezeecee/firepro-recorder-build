"""FACT-0303: original IL digest, distinct methods, ordinal witnesses and locked registry."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_cheer_art_literal_pair_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0303-skill-info-manager-cheer-art-literal-pair-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
d=w["shared_body"];body=bytes.fromhex(d["body_hex"])
assert (f["fact_id"],f["status"])==("FACT-0303","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_CHEER_ART_LITERAL_PAIR_SOURCE_V1",["DLL-001"])
assert len(body)==d["body_length"]==123 and hashlib.sha256(body).hexdigest()==d["body_sha256"]
assert [m["token"] for m in w["methods"]]==["0x06001160","0x06001161"]
assert [m["parent_call_sites"] for m in w["methods"]]==[[1179],[1197]]
assert w["parent"]["body_length"]==1396
assert [(c["literal"],c["return_ordinal"]) for c in w["literal_cases"]]==list(zip("EDCBAS",range(1,7)))
assert [c["branch_site"] for c in w["literal_cases"]]==[24,42,60,78,96,114]
assert [c["return_site"] for c in w["literal_cases"]]==[29,47,65,83,101,119]
assert w["empty_check"]["return_ordinal"]==w["default_return"]["ordinal"]==0
assert d["has_exception_section"] is False
assert sum(x["fact_id"]=="FACT-0303" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})>=302
assert reg["runtime_unlocked"] is False and reg["families"][-1]["runtime_eligible"] is False
print("SKILL INFO MANAGER CHEER ART LITERAL PAIR SOURCE SUMMARY: PASS")
