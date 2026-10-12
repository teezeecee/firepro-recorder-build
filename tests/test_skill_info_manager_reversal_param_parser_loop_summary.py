"""FACT-0294 original DLL reversal parser source-only static witness."""
import json,hashlib
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_info_manager_reversal_param_parser_loop.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0294-skill-info-manager-reversal-param-parser-loop.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
d=w["dll"];m=d["method"];body=bytes.fromhex(m["il_hex"])
assert (f["fact_id"],f["status"])==("FACT-0294","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_REVERSAL_PARAM_PARSER_LOOP_V1",["DLL-001"])
assert (m["token"],m["bytes"],m["sha256"])==("0x06001152",113,"cb0c54a49abf1719502656e10e4291b06d11867bcb0ade861cf8add160a07ae9")
assert len(body)==113 and hashlib.sha256(body).hexdigest()==m["sha256"]
assert [len(bytes.fromhex(x["hex"])) for x in m["segments"]]==[26,48,26,13]
assert (len(d["members"]),len(d["types"]),len(d["jumps"]),len(d["deps"]))==(5,2,4,3)
assert [x["target"] for x in d["jumps"]]==[100,74,112,26]
assert d["user_string"]["text"]=="end" and d["delimiter"]["value"]==44
assert d["deps"]["0x06001153"]["bytes"]==1396
assert sum(x["fact_id"]=="FACT-0294" for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
print("SKILL INFO MANAGER REVERSAL PARAM PARSER LOOP SUMMARY: PASS")
