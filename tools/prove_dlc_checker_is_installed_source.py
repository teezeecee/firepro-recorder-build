#!/usr/bin/env python3
"""FACT-0314: original DLCChecker.IsInstalled 12-byte singleton-to-SaveData bridge."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/dlc_checker_is_installed_source.summary.json"
def ck(test,message):
    if not test: raise AssertionError(message)
def verify(path,w):
    pe=Path(path).read_bytes();d=w["dll"];m=w["method"];fld=w["field"];cal=w["callee"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original DLL SHA/size")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
    fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16))
    il=md[9]
    ck((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],m["namespace"])),"original MethodDef row/name/owner/signature")
    ck(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"original complete tiny header")
    ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"original complete 12-byte IL")
    ck(p.field(pe,s,b,z,o,sb,bb,fm,int(fld["token"],16))==(fld["row"],(fld["owner"],""),fld["name"],fld["signature"]),"original SaveData.inst field row/owner/signature")
    ck(il[0:5]==bytes([int(fld["opcode"],16)])+struct.pack("<I",int(fld["token"],16)),"original static singleton operand")
    ck(il[5:6]==bytes([0x02]),"original ldarg.0 forwards DLCEnum input")
    cm=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(cal["token"],16))
    ck((cm[0],cm[1],cm[4],cm[5],cm[7],len(cm[9]),hashlib.sha256(cm[9]).hexdigest())==(cal["row"],int(cal["rva"],16),cal["name"],cal["signature"],(cal["owner"],cal["namespace"]),cal["body_length"],cal["body_sha256"]),"original matching SaveData.IsDLCInstalled callee")
    ck(il[6:11]==bytes([int(cal["opcode"],16)])+struct.pack("<I",int(cal["token"],16)),"original callvirt to SaveData.IsDLCInstalled")
    ck(il[11:12]==bytes([0x2A]),"original wrapper ret")
    return {"fact":"FACT-0314","original_source":"PASS","body_sha256":m["body_sha256"],"runtime_eligible":False}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_DLC_CHECKER_IS_INSTALLED_SOURCE_V1",["DLL-001"]),"witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True))
        print("PROVE_DLC_CHECKER_IS_INSTALLED_SOURCE: PASS");return 0
    except Exception as e:
        print("PROVE_DLC_CHECKER_IS_INSTALLED_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
