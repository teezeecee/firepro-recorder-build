#!/usr/bin/env python3
"""FACT-0306: exact original source GetSkillFilterName field and caller verification."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_get_skill_filter_name_source.summary.json"
def ck(v,label):
    if not v:raise AssertionError(label)
def verify(path,w):
    raw=Path(path).read_bytes();d=w["dll"];m=w["method"]
    ck((len(raw),hashlib.sha256(raw).hexdigest())==(d["size_bytes"],d["sha256"]),"original DLL identity")
    ss,q=p.secs(raw);st,hs,rows,pos=p.mdstreams(raw,ss,q)
    s,b,ix,z,o=p.tables(raw,st,hs,rows,pos)
    strings=st["#Strings"][0];blobs=st["#Blob"][0]
    fieldowners,methodowners=p.owner_maps(raw,rows,s,ix,z,o,strings)
    n=p.method(raw,ss,s,b,ix,z,o,strings,blobs,methodowners,int(m["token"],16));code=n[9]
    ck((n[0],n[1],n[4],n[5],n[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original MethodDef")
    ck(raw[p.off(ss,n[1]):n[8]].hex()==m["header"],"original fat header")
    ck((len(code),hashlib.sha256(code).hexdigest(),code.hex())==(m["body_length"],m["body_sha256"],m["body_hex"]),"complete original 54-byte IL")
    for f in w["fields"]:
        token=int(f["token"],16)
        ck(p.field(raw,s,b,z,o,strings,blobs,fieldowners,token)==(f["row"],(f["owner"],""),f["name"],f["signature"]),"original field metadata "+f["name"])
        sites=f.get("load_sites",[f.get("load_site")])
        op=0x7e if f["opcode"]=="ldsfld" else 0x7b
        for at in sites:
            ck(code[at:at+5]==bytes([op])+struct.pack("<I",token),"original field instruction "+f["name"]+" @"+str(at))
    for mr in w["memberrefs"]:
        token=int(mr["token"],16);at=o[10]+((token&0xffffff)-1)*z[10];rec=raw[at:at+z[10]]
        coded,at=p.rd(raw,at,z[10]-s-b);ni,at=p.rd(raw,at,s);bi,at=p.rd(raw,at,b)
        ck((rec.hex(),coded,p.s_at(raw,strings,ni),p.blob(raw,blobs,bi).hex())==(mr["row"],mr["class_coded"],mr["name"],mr["signature"]),"original MemberRef "+mr["name"])
        op=0x28 if mr["opcode"]=="call" else 0x6f
        for site in mr["sites"]:
            ck(code[site:site+5]==bytes([op])+struct.pack("<I",token),"original MemberRef site "+str(site))
    br=w["branch"];site=br["site"];rel=struct.unpack_from("<i",code,site+1)[0]
    ck((code[site],rel,site+5+rel)==(int(br["opcode"],16),br["relative"],br["target"]),"original brfalse target")
    seg=w["branches"]
    for branch in seg.values():
        ck(code[branch["site_start"]:branch["site_end"]].hex()==branch["source_hex"],"original full branch window")
    ck(code[23:25]==bytes.fromhex("1602") and code[47:49]==bytes.fromhex("0228"),"original branch argument setup")
    ck(code[30]==0x2a and code[53]==0x2a,"two original return sites")
    parent=w["caller"];pn=p.method(raw,ss,s,b,ix,z,o,strings,blobs,methodowners,int(parent["token"],16))
    ck((pn[4],pn[7])==(parent["name"],(parent["owner"],"")),"original caller metadata")
    cb=pn[9]
    ck((len(cb),hashlib.sha256(cb).hexdigest())==(parent["body_length"],parent["body_sha256"]),"original caller full IL")
    needle=bytes([0x28])+struct.pack("<I",int(m["token"],16))
    sites=[i for i in range(len(cb)-4) if cb[i:i+5]==needle]
    ck(sites==[parent["call_site"]] and parent["opcode"]=="call","one exact source direct caller")
    return {"fact":"FACT-0306","original_dll_source":"PASS","original_method_sha":m["body_sha256"],"caller_sites":sites,"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_GET_SKILL_FILTER_NAME_SOURCE_V1",["DLL-001"]),"witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_GET_SKILL_FILTER_NAME_SOURCE: PASS")
        return 0
    except Exception as e:
        print("PROVE_GET_SKILL_FILTER_NAME_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
