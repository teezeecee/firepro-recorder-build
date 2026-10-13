#!/usr/bin/env python3
"""FACT-0321 exact original retail ReturnBelt body, field, branch and reset loop validator."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
W=Path(__file__).resolve().parents[1]/"canonical/witnesses/CAP-R6-001/title_match_data_return_belt_source.summary.json"
def ck(v,msg):
    if not v: raise AssertionError(msg)
def verify(dll,w):
    pe=Path(dll).read_bytes();d=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original retail DLL identity")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos)
    sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    v=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=v[9]
    ck((v[0],v[1],v[4],v[5],v[7],pe[p.off(ss,v[1]):v[8]].hex())==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],m["namespace"]),m["header"]),"original MethodDef row/owner/header")
    ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"complete original 55-byte IL")
    for f in w["fields"]:
        token=int(f["token"],16)
        ck(p.field(pe,s,b,z,o,sb,bb,fm,token)==(f["row"],(f["owner"],f["namespace"]),f["name"],f["signature"]),"original field metadata "+f["token"])
        j=f["site"];ck(il[j:j+5]==b"\x7b"+struct.pack("<I",token),"original ldfld site "+f["token"])
        ck((il[f["index_site"]],il[f["value_site"]],il[f["store_site"]])==(0x06,int(f["value_opcode"],16),int(f["store_opcode"],16)),"original indexed constant and typed array-store "+f["token"])
    for branch in w["branches"]:
        j=branch["site"];delta=struct.unpack_from("<i",il,j+1)[0]
        ck((il[j],delta,j+5+delta)==(int(branch["opcode"],16),branch["delta"],branch["target"]),"original loop branch "+str(j))
    loop=w["loop"]
    ck(il[0:2].hex()==loop["init_hex"],"initial local index")
    ck(il[43:47].hex()==loop["loop_update_hex"],"index increment")
    ck(il[47:54].hex()==loop["loop_test_hex"],"original literal four and conditional back branch")
    ck((loop["loop_body_start"],loop["return_site"],il[54])==(7,54,int(loop["return_opcode"],16)),"source body/return bounds")
    ck(loop["source_index_values"]==[0,1,2,3],"bounded loop source counter range")
    ck(il.count(b"\x7b")==4 and all(il[site]==0x9e for site in (15,24,33)) and il[42]==0x9c,"exactly four typed array sites")
    return {"fact":"FACT-0321","source_proof":"PASS","body_bytes":55,"fields":4,"array_writes_per_source_iteration":4,"runtime_eligible":False}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);a=ap.parse_args()
    try:
        w=json.loads(W.read_text());ck(w["dataset_id"]=="DLL_TITLE_MATCH_DATA_RETURN_BELT_SOURCE_V1" and w["source_ids"]==["DLL-001"],"witness identity")
        print(json.dumps(verify(a.dll,w),sort_keys=True));print("PROVE_TITLE_MATCH_DATA_RETURN_BELT_SOURCE: PASS");return 0
    except Exception as e:
        print("PROVE_TITLE_MATCH_DATA_RETURN_BELT_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
