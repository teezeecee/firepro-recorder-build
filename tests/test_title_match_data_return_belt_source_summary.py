"""FACT-0321 original ReturnBelt 55-byte summary, original typed array stores and bounded branch offsets."""
import hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/title_match_data_return_belt_source.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0321-title-match-data-return-belt-source.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
assert (f["fact_id"],f["status"])==("FACT-0321","PROVEN_DLL")
assert w["dataset_id"]=="DLL_TITLE_MATCH_DATA_RETURN_BELT_SOURCE_V1" and w["source_ids"]==["DLL-001"]
m=w["method"];il=bytes.fromhex(m["body_hex"])
assert (m["token"],m["owner"],m["name"],len(il))==("0x060011B1","TitleMatch_Data","ReturnBelt",55)
assert hashlib.sha256(il).hexdigest()==m["body_sha256"]
assert il[:2]==b"\x16\x0a" and il[43:47]==b"\x06\x17\x58\x0a"
assert il[47:54]==b"\x06\x1a\x3f\xd1\xff\xff\xff" and il[54]==0x2a
assert w["loop"]["source_index_values"]==[0,1,2,3]
for row in w["fields"]:
    j=row["site"]; token=int(row["token"],16)
    assert il[j:j+5]==b"\x7b"+struct.pack("<I",token)
    assert il[row["index_site"]]==0x06 and il[row["value_site"]]==int(row["value_opcode"],16)
    assert il[row["store_site"]]==int(row["store_opcode"],16)
assert len(w["fields"])==4 and [x["name"] for x in w["fields"]]==["wrestlerID","CtrlNo","Costume","IsSecond"]
assert [x["value"] for x in w["fields"]]==[-1,-1,0,0]
assert [x["store_opcode"] for x in w["fields"]]==["0x9E","0x9E","0x9E","0x9C"]
for row in w["branches"]:
    j=row["site"]; delta=struct.unpack_from("<i",il,j+1)[0]
    assert (il[j],delta,j+5+delta)==(int(row["opcode"],16),row["delta"],row["target"])
assert [(x["site"],x["target"]) for x in w["branches"]]==[(2,47),(49,7)]
assert len(reg["families"])>=320 and len(set(x["family_id"] for x in reg["families"]))==len(reg["families"])
assert len(set(x["fact_id"] for x in reg["families"]))==len(reg["families"])
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0321")["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
print("TITLE MATCH DATA RETURN BELT SOURCE SUMMARY: PASS")
