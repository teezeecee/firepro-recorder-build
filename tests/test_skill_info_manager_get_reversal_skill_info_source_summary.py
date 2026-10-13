"""FACT-0305: source witness, original 32-byte IL and append-safe locked registry."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_get_reversal_skill_info_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0305-skill-info-manager-get-reversal-skill-info-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];body=bytes.fromhex(m["il_hex"])
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_GET_REVERSAL_SKILL_INFO_SOURCE_V1",["DLL-001"])
assert (f["fact_id"],f["status"])==("FACT-0305","PROVEN_DLL")
assert m["token"]=="0x06001165" and m["owner"]=="SkillInfoManager"
assert len(body)==m["code_bytes"]==32 and hashlib.sha256(body).hexdigest()==m["code_sha256"]
assert body.hex()=="03163c02000000142a031f793f02000000142a027bdc0e0004036f5907000a2a"
assert w["field"]["token"]=="0x04000EDC" and w["memberref"]["token"]=="0x0A000759"
assert [(x["il"],x["target"]) for x in w["bounds"]["branches"]]==[(2,9),(12,19)]
assert (w["bounds"]["lower"],w["bounds"]["upper"])==(0,121)
assert [x["sites"] for x in w["direct_callers"]]==[[151],[189,301],[180],[181]]
assert sum(x["fact_id"]=="FACT-0305" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})>=304
assert reg["runtime_unlocked"] is False
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0305")["runtime_eligible"] is False
print("SKILL INFO MANAGER GET REVERSAL SKILL INFO SOURCE SUMMARY: PASS")
