#!/usr/bin/env python3
"""FACT-0316: original retail DLCManager.Update loop and all six direct MethodDef calls."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/dlc_manager_update_source.summary.json"
def ck(ok,msg):
    if not ok:raise AssertionError(msg)
def verify(path,w):
    pe=Path(path).read_bytes();d=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original retail DLL")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
    fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=md[9]
    ck((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],m["namespace"])),"exact Update MethodDef row, signature and owner")
    ck(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"exact fat method header")
    ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"full original 114-byte IL")
    for fld in w["fields"]:
        tok=int(fld["token"],16)
        ck(p.field(pe,s,b,z,o,sb,bb,fm,tok)==(fld["row"],(fld["owner"],fld["namespace"]),fld["name"],fld["signature"]),"exact FieldDef and original TypeDef owner "+fld["token"])
        site=fld["site"]
        ck(il[site:site+5]==bytes([int(fld["opcode"],16)])+struct.pack("<I",tok),"original field opcode/operand "+fld["token"])
    for call in w["callees"]:
        tok=int(call["token"],16);target=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        ck((target[0],target[1],target[4],target[5],target[7],len(target[9]),hashlib.sha256(target[9]).hexdigest())==(call["row"],int(call["rva"],16),call["name"],call["signature"],(call["owner"],call["namespace"]),call["body_length"],call["body_sha256"]),"original called MethodDef + full body "+call["token"])
        site=call["site"];pat=bytes([int(call["opcode"],16)])+struct.pack("<I",tok)
        ck(il[site:site+5]==pat,"exact source call "+call["token"])
        ck([i for i in range(len(il)-4) if il[i:i+5]==pat]==[site],"unique bounded direct site "+call["token"])
    for branch in w["branches"]:
        i=branch["site"];delta=struct.unpack_from("<i",il,i+1)[0]
        ck((il[i],delta,i+5+delta)==(int(branch["opcode"],16),branch["delta"],branch["target"]),"original branch target "+str(i))
    ck(il[13:17]==bytes([0x07,0x08,0x94,0x0A]),"DLCNums index read and store local")
    ck(il[87:89]==bytes([0x06,0x94]),"dlcVersion indexed element read")
    ck(il[100:104]==bytes([0x08,0x17,0x58,0x0C]),"loop counter increment")
    ck(il[104:108]==bytes([0x08,0x07,0x8E,0x69]) and il[113:114]==bytes([0x2A]),"loop length and return")
    return {"fact":"FACT-0316","original_dll_source":"PASS","fields":len(w["fields"]),"callee_count":len(w["callees"]),"branches":len(w["branches"]),"runtime_eligible":False}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_DLC_MANAGER_UPDATE_SOURCE_V1",["DLL-001"]),"source witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_DLC_MANAGER_UPDATE_SOURCE: PASS");return 0
    except Exception as e:
        print("PROVE_DLC_MANAGER_UPDATE_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
