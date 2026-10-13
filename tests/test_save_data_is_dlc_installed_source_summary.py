"""FACT-0312: byte-exact source-only SaveData.IsDLCInstalled witness and registry."""
import hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/save_data_is_dlc_installed_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0312-save-data-is-dlc-installed-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];il=bytes.fromhex(m["body_hex"])
assert (f["fact_id"],f["status"])==("FACT-0312","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_SAVE_DATA_IS_DLC_INSTALLED_SOURCE_V1",["DLL-001"])
assert m["token"]=="0x060051C9" and len(il)==m["body_length"]==45
assert hashlib.sha256(il).hexdigest()==m["body_sha256"]
assert [(x["site"],x["target"]) for x in w["branches"]]==[(6,13),(21,43),(28,41)]
assert [(x["site"],x["target"]) for x in w["calls"]]==[(1,"0x06001033"),(35,"0x060051C9")]
assert w["field"]["token"]=="0x0400650C" and w["field"]["site"]==14
assert [c["sites"] for c in w["direct_callers"]]==[[6],[39]]
assert len(reg["families"])>=311 and len(set(x["family_id"] for x in reg["families"]))==len(reg["families"])
assert sum(x["fact_id"]=="FACT-0312" for x in reg["families"])==1
assert reg["runtime_unlocked"] is False
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0312")["runtime_eligible"] is False
print("SAVE DATA IS DLC INSTALLED SOURCE SUMMARY: PASS")
