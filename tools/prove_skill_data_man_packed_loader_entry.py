#!/usr/bin/env python3
"""FACT-0264 source-byte check for original SkillDataMan packed-resource entry."""
import argparse, hashlib, json, struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_packed_loader_entry.summary.json"

def need(test,msg):
    if not test: raise ValueError(msg)

def verify(path,w):
    pe=Path(path).read_bytes(); d=w["dll"]; m=d["method"]
    need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"DLL identity")
    ss,q=base.secs(pe); st,hs,rows,p=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
    sb=st["#Strings"][0];bb=st["#Blob"][0];_,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    row,rva,impl,flags,name,sig,plist,owner,start,body=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06005256)
    need((row,rva,impl,flags,name,sig,owner)==(m["methoddef_row_hex"],int(m["rva"],16),0,0x0081,m["name"],m["signature_blob_hex"],(m["owner"],"")),"exact MethodDef metadata")
    need(pe[base.off(ss,rva):start].hex()==m["header_hex"],"method header")
    need(body.hex()==m["body_hex"] and len(body)==m["code_size"]==51 and hashlib.sha256(body).hexdigest()==m["code_sha256"],"exact original code")
    us=st["#US"][0]+0xCEAC
    need(pe[us]==15 and pe[us+1:us+15-1].decode("utf-16-le")=="fprwaza","literal #US")
    need(w["dll"]["resource_string"]=={"token":"0x7000CEAC","value":"fprwaza"},"witness string")
    sites=[(0,0x72,0x7000CEAC),(6,0x28,0x0A00055A),(13,0x28,0x0A0006DA),
           (18,0x75,0x010000E4),(26,0x6F,0x0A00014F),(31,0x28,0x06005257),
           (37,0x28,0x0A0006DF),(42,0x28,0x0A00055A)]
    need(len(d["exact_token_sites"])==len(sites),"site count")
    for il,op,tok in sites:
        need(body[il]==op and struct.unpack_from("<I",body,il+1)[0]==tok,"IL token "+hex(il))
        need(int(next(x["operand"] for x in d["exact_token_sites"] if int(x["il"],16)==il),16)==tok,"witness site "+hex(il))
    need(d["exact_token_sites"][0]["literal"]=="fprwaza","source label")
    need(d["exact_token_sites"][3]["name"]=="UnityEngine.TextAsset","TypeRef label")
    refwidth=4 if max(rows.get(k,0) for k in (2,1,26,6,27))>=8192 else 2
    for mr in d["memberrefs"]:
        rid=int(mr["token"],16)&0xffffff; p=o[10]+(rid-1)*z[10]
        need(pe[p:p+z[10]].hex()==mr["raw_row_hex"],"exact MemberRef row")
        parent,p=base.rd(pe,p,refwidth);n,p=base.rd(pe,p,s);blobid,p=base.rd(pe,p,b)
        need((parent,base.s_at(pe,sb,n),base.blob(pe,bb,blobid).hex())==(mr["parent_coded"],mr["name"],mr["signature_blob_hex"]),"MemberRef metadata")
    refrow=0xE4; typewidth=4 if max(rows.get(k,0) for k in (0,26,35,1))>=16384 else 2
    p=o[1]+(refrow-1)*z[1]+typewidth
    nameidx,p=base.rd(pe,p,s);nsidx,p=base.rd(pe,p,s)
    need((base.s_at(pe,sb,nameidx),base.s_at(pe,sb,nsidx))==("TextAsset","UnityEngine"),"TextAsset TypeRef")
    for rec in ("child","neighbor"):
        c=d[rec]; cm=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(c["token"],16))
        need((cm[1],cm[4],len(cm[9]),hashlib.sha256(cm[9]).hexdigest())==(int(c["rva"],16),c["name"],c["code_size"],c["code_sha256"]),rec+" boundary")
    need(d["branch_count"]==0 and m["instruction_count"]==19,"exact straight-line layout")
    return {"method_token":m["token"],"raw_code_size":len(body),"raw_code_sha256":hashlib.sha256(body).hexdigest(),
            "resource_name":"fprwaza","child_method":d["child"]["token"],"child_body_open":True}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        need(w["dataset_id"]=="DLL_SKILL_DATA_MAN_PACKED_LOADER_ENTRY_V1" and w["source_ids"]==["DLL-001"],"witness id")
        print(json.dumps(verify(args.dll,w),indent=2,sort_keys=True))
        print("PROVE_SKILL_DATA_MAN_PACKED_LOADER_ENTRY: PASS");return 0
    except Exception as exc:
        print("PROVE_SKILL_DATA_MAN_PACKED_LOADER_ENTRY: FAIL",exc);return 1

if __name__=="__main__": raise SystemExit(main())
