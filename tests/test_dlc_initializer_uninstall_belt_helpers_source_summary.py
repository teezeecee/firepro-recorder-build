"""FACT-0320 twin DLCInitializer retail-source body/EH summary regression."""
import hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/dlc_initializer_uninstall_belt_helpers_source.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0320-dlc-initializer-uninstall-belt-helpers-source.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
assert (f["fact_id"],f["status"])==("FACT-0320","PROVEN_DLL")
assert w["dataset_id"]=="DLL_DLC_INITIALIZER_UNINSTALL_BELT_HELPERS_SOURCE_V1" and w["source_ids"]==["DLL-001"]
assert w["dll"]["size_bytes"]==8171008 and len(w["methods"])==2
a,b=w["methods"]; assert (a["token"],b["token"])==("0x06001039","0x0600103B")
bb=[]
for m in w["methods"]:
    il=bytes.fromhex(m["body_hex"]);bb.append(il)
    assert len(il)==m["body_length"]==119 and hashlib.sha256(il).hexdigest()==m["body_sha256"]
    assert il[0]==int(m["first_opcode"],16) and il[1]==0x0a and m["raw_dlc_value"] in (2,5)
    e=bytes.fromhex(m["eh_section_hex"]);assert len(e)==16 and e.hex()=="01100000020014005468000e00000000"
    q=w["eh"]; assert (e[0],e[1],struct.unpack_from("<H",e,4)[0],struct.unpack_from("<H",e,6)[0],e[8],struct.unpack_from("<H",e,9)[0],e[11])==(q["kind"],q["size_bytes"],q["flags"],q["try_start"],q["try_length"],q["handler_start"],q["handler_length"])
    for record in w["fields"]+w["direct_callees"]:
        for site in record["sites"]:
            assert il[site:site+5]==bytes([int(record["opcode"],16)])+struct.pack("<I",int(record["token"],16))
    for record in w["unresolved_numeric_references"]:
        prefix=b"\xfe\x16" if record["opcode"]=="0xFE16" else bytes([int(record["opcode"],16)])
        j=record["site"]; assert il[j:j+len(prefix)+4]==prefix+struct.pack("<I",int(record["token"],16))
    for record in w["branches"]:
        j=record["site"];d=struct.unpack_from("<i",il,j+1)[0]
        assert (il[j],d,j+5+d)==(int(record["opcode"],16),record["delta"],record["target"])
    assert il[117:119]==b"\xdc\x2a" and il[68:71]==b"\x11\x04\x06"
assert bb[0][1:]==bb[1][1:] and bb[0][0]==0x18 and bb[1][0]==0x1b
assert len(w["fields"])==4 and len(w["direct_callees"])==3
assert len(w["unresolved_numeric_references"])==5 and len(w["branches"])==6
ids=[x["family_id"] for x in reg["families"]];facts=[x["fact_id"] for x in reg["families"]]
assert len(reg["families"])==319 and len(set(ids))==len(ids) and len(set(facts))==len(facts)
assert reg["families"][-1]["fact_id"]=="FACT-0320" and reg["families"][-1]["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
print("DLC INITIALIZER UNINSTALL BELT HELPERS SOURCE SUMMARY: PASS")
