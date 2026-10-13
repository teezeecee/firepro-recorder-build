#!/usr/bin/env python3
"""FACT-0315 full original IsDownloaded source and bounded caller proof."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/dlc_checker_is_downloaded_source.summary.json"
def ck(ok,msg):
    if not ok:raise AssertionError(msg)
def verify(path,w):
    pe=Path(path).read_bytes();d=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original DLL")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
    _,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=md[9]
    ck((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],m["namespace"])),"original method metadata")
    ck(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"original tiny header")
    ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"original whole IL")
    ck(il[0:1]==bytes([0x02]) and il[16:17]==bytes([0x2A]),"original arg and return")
    cal=w["methoddef_callee"];cm=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(cal["token"],16))
    ck((cm[0],cm[1],cm[4],cm[5],cm[7],len(cm[9]),hashlib.sha256(cm[9]).hexdigest())==(cal["row"],int(cal["rva"],16),cal["name"],cal["signature"],(cal["owner"],cal["namespace"]),cal["body_length"],cal["body_sha256"]),"original GetDLCID callee")
    ck(il[1:6]==bytes([0x28])+struct.pack("<I",int(cal["token"],16)),"original GetDLCID call")
    for ty in w["typerefs"]:
        tok=int(ty["token"],16);r=tok&0xffffff;at=o[1]+(r-1)*z[1];row=pe[at:at+z[1]]
        coded,at=p.rd(pe,at,z[1]-2*s);ni,at=p.rd(pe,at,s);nsi,at=p.rd(pe,at,s)
        ck((row.hex(),coded,p.s_at(pe,sb,ni),p.s_at(pe,sb,nsi))==(ty["row"],ty["resolution_scope_coded"],ty["name"],ty["namespace"]),"original TypeRef")
    for mr in w["memberrefs"]:
        tok=int(mr["token"],16);at=o[10]+((tok&0xffffff)-1)*z[10];row=pe[at:at+z[10]]
        coded,at=p.rd(pe,at,z[10]-s-b);ni,at=p.rd(pe,at,s);bi,at=p.rd(pe,at,b)
        ck((row.hex(),coded,p.s_at(pe,sb,ni),p.blob(pe,bb,bi).hex())==(mr["row"],mr["class_coded"],mr["name"],mr["signature"]),"original MemberRef")
        ck((coded&7)==1 and (0x01000000|(coded>>3))==int(mr["owner_type_token"],16),"original member parent")
        i=mr["site"];ck(il[i:i+5]==bytes([int(mr["opcode"],16)])+struct.pack("<I",tok),"original member callsite")
    caller=w["direct_caller"];cm=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(caller["token"],16));body=cm[9]
    ck((cm[4],cm[7],len(body),hashlib.sha256(body).hexdigest())==(caller["name"],(caller["owner"],caller["namespace"]),caller["body_length"],caller["body_sha256"]),"original caller")
    pat=bytes([int(caller["opcode"],16)])+struct.pack("<I",int(m["token"],16))
    ck([i for i in range(len(body)-4) if body[i:i+5]==pat]==[caller["site"]],"original caller site")
    return {"fact":"FACT-0315","original_dll_source":"PASS","runtime_eligible":False}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"));ck((w["dataset_id"],w["source_ids"])==("DLL_DLC_CHECKER_IS_DOWNLOADED_SOURCE_V1",["DLL-001"]),"witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_DLC_CHECKER_IS_DOWNLOADED_SOURCE: PASS");return 0
    except Exception as e:
        print("PROVE_DLC_CHECKER_IS_DOWNLOADED_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
