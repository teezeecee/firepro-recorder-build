"""FACT-0311: source-pinned original SkillInfo DLC byte loops."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_dlc_flag_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0311-skill-info-dlc-flag-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
assert (f["fact_id"],f["status"])==("FACT-0311","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_DLC_FLAG_SOURCE_V1",["DLL-001"])
assert [m["token"] for m in w["methods"]]==["0x06001145","0x06001146","0x06001147","0x06001148"]
assert [m["body_length"] for m in w["methods"]]==[65,36,59,36]
for m in w["methods"]:
    b=bytes.fromhex(m["body_hex"])
    assert len(b)==m["body_length"] and hashlib.sha256(b).hexdigest()==m["body_sha256"]
assert [x["sites"] for x in w["direct_callers"]]==[[21],[62],[119],[86],[1]]
assert [x["token"] for x in w["fields"]]==["0x04000ED4","0x040064EC"]
assert len(reg["families"])>=310 and len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert sum(x["fact_id"]=="FACT-0311" for x in reg["families"])==1
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0311")["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
print("SKILL INFO DLC FLAG SOURCE SUMMARY: PASS")
