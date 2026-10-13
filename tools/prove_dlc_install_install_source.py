#!/usr/bin/env python3
"""FACT-0318 byte-exact original DLCInstall.Install and bounded callee/field sources."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/dlc_install_install_source.summary.json"
def ck(ok,msg):
    if not ok:raise AssertionError(msg)
def verify(path,w):
    pe=Path(path).read_bytes();d=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original DLL SHA and length")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
    fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=md[9]
    ck((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],m["namespace"])),"exact original MethodDef row/name/owner/signature")
    ck(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"original method header")
    ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"original complete 242-byte IL")
    for f in w["fields"]:
        token=int(f["token"],16)
        ck(p.field(pe,s,b,z,o,sb,bb,fm,token)==(f["row"],(f["owner"],f["namespace"]),f["name"],f["signature"]),"original FieldDef ownership "+f["token"])
        i=f["site"];ck(il[i:i+5]==bytes([int(f["opcode"],16)])+struct.pack("<I",token),"original FieldDef operand")
    for c in w["callees"]:
        token=int(c["token"],16);v=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,token)
        ck((v[0],v[1],v[4],v[5],v[7],len(v[9]),hashlib.sha256(v[9]).hexdigest())==(c["row"],int(c["rva"],16),c["name"],c["signature"],(c["owner"],c["namespace"]),c["body_length"],c["body_sha256"]),"original MethodDef/callee body "+c["token"])
        pat=bytes([int(c["opcode"],16)])+struct.pack("<I",token)
        ck([i for i in range(len(il)-4) if il[i:i+5]==pat]==c["sites"],"exact bounded callee site(s) "+c["token"])
    for br in w["conditional_branches"]+w["common_target_branches"]:
        i=br["site"];delta=struct.unpack_from("<i",il,i+1)[0]
        ck((il[i],delta,i+5+delta)==(int(br["opcode"],16),br["delta"],br["target"]),"original 32-bit branch "+str(i))
    sw=w["switch"];i=sw["site"]
    ck(il[i]==int(sw["opcode"],16) and struct.unpack_from("<I",il,i+1)[0]==sw["case_count"],"switch count")
    start=i+5+4*sw["case_count"]
    ck(start==sw["fallthrough_target"],"switch fallthrough")
    deltas=[struct.unpack_from("<i",il,i+5+4*k)[0] for k in range(sw["case_count"])]
    ck(deltas==sw["relative_deltas"] and [start+d for d in deltas]==sw["targets"],"all 13 original switch targets")
    end=w["source_tail"]
    ck(il[end["start"]:].hex()==end["hex"],"exact common SaveData.dlcVersion assignment tail")
    ck(il[19:21]==bytes([0x02,0x19]) and il[26:28]==bytes([0x06,0x18]),"raw 3 vs raw 2 dependency")
    ck(il[39:42]==bytes([0x02,0x1F,0x09]),"raw DLC index 9")
    return {"fact":"FACT-0318","original_source":"PASS","fields":len(w["fields"]),"callee_targets":len(w["callees"]),"switch_cases":sw["case_count"],"runtime_eligible":False}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);a=ap.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"));ck((w["dataset_id"],w["source_ids"])==("DLL_DLC_INSTALL_INSTALL_SOURCE_V1",["DLL-001"]),"witness identity")
        print(json.dumps(verify(a.dll,w),sort_keys=True));print("PROVE_DLC_INSTALL_INSTALL_SOURCE: PASS");return 0
    except Exception as e:
        print("PROVE_DLC_INSTALL_INSTALL_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
