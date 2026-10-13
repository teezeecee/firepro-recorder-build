"""FACT-0317 original retail DLCManager DLCNums static initializer and exact 13 values."""
import hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/dlc_manager_static_dlcnums_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((R/"canonical/facts/FACT-0317-dlc-manager-static-dlcnums-source.json").read_text(encoding="utf-8"))
reg=json.loads((R/"canonical/transition_registry.json").read_text(encoding="utf-8"))
assert f["fact_id"]=="FACT-0317" and f["status"]=="PROVEN_DLL"
assert (w["dataset_id"],w["source_ids"])==("DLL_DLC_MANAGER_STATIC_DLCNUMS_SOURCE_V1",["DLL-001"])
m=w["method"];il=bytes.fromhex(m["body_hex"])
assert m["token"]=="0x0600103E" and m["name"]==".cctor" and len(il)==24
assert hashlib.sha256(il).hexdigest()==m["body_sha256"]
assert il[:2]==bytes([0x1F,0x0D])
for key in ("array_type","initializer_field","initialize_array","target_field"):
    x=w[key];i=x["site"]
    assert il[i:i+5]==bytes([int(x["opcode"],16)])+struct.pack("<I",int(x["token"],16))
assert il[7]==0x25 and il[23]==0x2A
data=w["field_rva"];raw=bytes.fromhex(data["raw_hex"])
assert len(raw)==data["byte_length"]==52 and hashlib.sha256(raw).hexdigest()==data["raw_sha256"]
assert list(struct.unpack("<13i",raw))==data["raw_int32_le"]==[0,2,3,1,4,5,6,7,8,9,10,11,12]
assert data["field_token"]==w["initializer_field"]["token"]
assert w["initialize_array"]["name"]=="InitializeArray" and w["target_field"]["name"]=="DLCNums"
families=reg["families"];ids=[x["family_id"] for x in families];facts=[x["fact_id"] for x in families]
assert len(families)>=316 and len(ids)==len(set(ids)) and len(facts)==len(set(facts))
assert sum(x=="FACT-0317" for x in facts)==1
assert next(x for x in families if x["fact_id"]=="FACT-0317")["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
print("DLC MANAGER STATIC DLCNUMS SOURCE SUMMARY: PASS")
