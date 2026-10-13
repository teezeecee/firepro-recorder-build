#!/usr/bin/env python3
"""FACT-0312: byte-exact SaveData.IsDLCInstalled and bounded retail caller proof."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/save_data_is_dlc_installed_source.summary.json"
def ck(condition,message):
    if not condition:raise AssertionError(message)
def verify(path,w):
    pe=Path(path).read_bytes();d=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original retail DLL SHA")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
    fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=md[9]
    ck((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],m["namespace"])),"original method metadata")
    ck(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"original tiny header")
    ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"complete original 45-byte IL")
    f=w["field"];tok=int(f["token"],16)
    ck(p.field(pe,s,b,z,o,sb,bb,fm,tok)==(f["row"],(f["owner"],""),f["name"],f["signature"]),"original dlcVersion field identity and type")
    ck(il[f["site"]:f["site"]+5]==bytes([int(f["opcode"],16)])+struct.pack("<I",tok),"original ldfld operand")
    for call in w["calls"]:
        tok=int(call["target"],16);md2=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        ck((md2[0],md2[4],md2[5],md2[7],len(md2[9]),hashlib.sha256(md2[9]).hexdigest())==(call["row"],call["name"],call["signature"],(call["owner"],call["namespace"]),call["body_length"],call["body_sha256"]),"original called MethodDef metadata/body "+call["target"])
        ck(il[call["site"]:call["site"]+5]==bytes([int(call["opcode"],16)])+struct.pack("<I",tok),"original call IL site "+str(call["site"]))
    for branch in w["branches"]:
        site=branch["site"]; delta=struct.unpack_from("<i",il,site+1)[0]
        ck((il[site],delta,site+5+delta)==(int(branch["opcode"],16),branch["relative"],branch["target"]),"original branch "+str(site))
    ck(il[11:13]==bytes.fromhex("162a") and il[19:21]==bytes.fromhex("0394"),"owner-false return and original indexed int32 load")
    ck(il[26:28]==bytes.fromhex("0319") and il[33:35]==bytes.fromhex("0218"),"index 3 comparison and recursive index 2 argument")
    ck(il[40:]==bytes.fromhex("2a172a162a"),"original recursive/true/false return tails")
    for caller in w["direct_callers"]:
        tok=int(caller["token"],16);cm=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok);body=cm[9]
        ck((cm[4],cm[7],len(body),hashlib.sha256(body).hexdigest())==(caller["name"],(caller["owner"],caller["namespace"]),caller["body_length"],caller["body_sha256"]),"original caller whole-body identity")
        pattern=bytes([int(caller["opcode"],16)])+struct.pack("<I",int(m["token"],16))
        sites=[i for i in range(len(body)-4) if body[i:i+5]==pattern]
        ck(sites==caller["sites"],"original caller direct sites")
    return {"fact":"FACT-0312","original_dll_source":"PASS","exact_method_il_sha256":m["body_sha256"],"pinned_direct_callers":len(w["direct_callers"]),"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SAVE_DATA_IS_DLC_INSTALLED_SOURCE_V1",["DLL-001"]),"source witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_SAVE_DATA_IS_DLC_INSTALLED_SOURCE: PASS");return 0
    except Exception as ex:
        print("PROVE_SAVE_DATA_IS_DLC_INSTALLED_SOURCE: FAIL",str(ex));return 1
if __name__=="__main__":raise SystemExit(main())
