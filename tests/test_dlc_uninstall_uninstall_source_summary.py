"""FACT-0319 original source summary, all numeric dispatch and store sites."""
import hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/dlc_uninstall_uninstall_source.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0319-dlc-uninstall-uninstall-source.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
assert f["fact_id"]=="FACT-0319" and f["status"]=="PROVEN_DLL"
assert w["dataset_id"]=="DLL_DLC_UNINSTALL_UNINSTALL_SOURCE_V1" and w["source_ids"]==["DLL-001"]
m=w["method"]; il=bytes.fromhex(m["body_hex"])
assert (m["token"],m["owner"],len(il))==("0x0600103F","DLCUninstall",266)
assert hashlib.sha256(il).hexdigest()==m["body_sha256"]
sw=w["switch"]; i=sw["site"]; n=struct.unpack_from("<I",il,i+1)[0];start=i+5+4*n
assert (i,il[i],n,start)==(7,0x45,13,64)
assert [start+struct.unpack_from("<i",il,i+5+4*j)[0] for j in range(n)]==sw["targets"]
assert w["ret_site"]==265 and il[265]==0x2a
assert len(w["fields"])==1 and len(w["callees"])==3 and len(w["common_return_branches"])==14
for b in w["common_return_branches"]:
 j=b["site"]; assert il[j]==0x38 and j+5+struct.unpack_from("<i",il,j+1)[0]==265
for c in w["callees"]:
 j=c["site"]; assert il[j:j+5]==b"\x28"+struct.pack("<I",int(c["token"],16))
for q in w["index_write_sites"]:
 k=q["index"];j=q["field_site"]
 assert q["case_target"]==sw["targets"][k] and il[j-1]==6
 assert il[j:j+5]==b"\x7b"+struct.pack("<I",0x0400650c)
 s=j+5
 if k<=8: assert il[s]==0x16+k; s+=1
 else: assert il[s:s+2]==bytes([0x1f,k]); s+=2
 assert il[s:s+2]==b"\x16\x9e" and q["value"]==0
assert il[sw["fallthrough_target"]]==0x38
ids=[x["family_id"] for x in reg["families"]]; facts=[x["fact_id"] for x in reg["families"]]
assert len(reg["families"])>=318 and len(ids)==len(set(ids)) and len(facts)==len(set(facts))
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0319")["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
print("DLC UNINSTALL UNINSTALL SOURCE SUMMARY: PASS")
