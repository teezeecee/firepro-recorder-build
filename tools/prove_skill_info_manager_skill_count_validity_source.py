#!/usr/bin/env python3
"""FACT-0304: prove two original tiny dictionary lookup bodies and caller sites."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_skill_count_validity_source.summary.json"
def ck(cond,what):
    if not cond:raise AssertionError(what)
def verify(path,w):
    raw=Path(path).read_bytes();d=w["dll"]
    ck((len(raw),hashlib.sha256(raw).hexdigest())==(d["size_bytes"],d["sha256"]),"original DLL identity")
    ss,q=p.secs(raw);st,hs,rows,pos=p.mdstreams(raw,ss,q);s,b,ix,z,o=p.tables(raw,st,hs,rows,pos)
    sb=st["#Strings"][0];bb=st["#Blob"][0]
    fields,owners=p.owner_maps(raw,rows,s,ix,z,o,sb)
    f=w["source_field"];token=int(f["token"],16)
    ck(p.field(raw,s,b,z,o,sb,bb,fields,token)==(f["row"],(f["owner"],""),f["name"],f["signature"]),"original source field identity")
    mrmap={x["token"]:x for x in w["memberrefs"]}
    results=[]
    for m in w["methods"]:
        token=int(m["token"],16)
        v=p.method(raw,ss,s,b,ix,z,o,sb,bb,owners,token)
        body=v[9]
        ck((v[0],v[1],v[4],v[5],v[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original method metadata "+m["name"])
        ck(raw[p.off(ss,v[1]):v[8]].hex()==m["header"],"original tiny method header")
        ck((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"complete original IL "+m["name"])
        ck(body[1:6]==bytes([0x7b])+struct.pack("<I",int(f["token"],16)),"original skillInfoList field operand")
        mr=mrmap[m["memberref_token"]];t=int(mr["token"],16)
        a=o[10]+((t&0xffffff)-1)*z[10];record=raw[a:a+z[10]]
        coded,a=p.rd(raw,a,z[10]-s-b);ni,a=p.rd(raw,a,s);bi,a=p.rd(raw,a,b)
        ck((record.hex(),p.s_at(raw,sb,ni),p.blob(raw,bb,bi).hex())==(mr["row"],mr["name"],mr["signature"]),"original dictionary MemberRef")
        site=m["call_site"]
        ck(body[site:site+5]==bytes([0x6f])+struct.pack("<I",t),"original callvirt instruction")
        ck(body[-1]==0x2a,"source ret")
        if m["name"]=="GetSkillNum":
            ck(body==bytes.fromhex("027bda0e00046f5807000a2a"),"get_Count exact body")
        else:
            c=w["validity_branches"];at=c["conditional_site"]
            ck(body[at]==int(c["opcode"],16) and struct.unpack_from("<i",body,at+1)[0]==c["relative"] and at+5+c["relative"]==c["false_target"],"branch on ContainsKey false")
            ck(body[c["true_site"]:c["true_site"]+2].hex()==c["true_hex"] and body[c["false_site"]:c["false_site"]+2].hex()==c["false_hex"],"source return 1 versus 0")
        results.append({"token":m["token"],"name":m["name"],"bytes":len(body)})
    cs=[]
    for c in w["direct_callers"]:
        v=p.method(raw,ss,s,b,ix,z,o,sb,bb,owners,int(c["token"],16))
        ck((v[4],v[7])==(c["name"],(c["owner"],"")),"source caller identity")
        body=v[9]
        ck((len(body),hashlib.sha256(body).hexdigest())==(c["body_length"],c["body_sha256"]),"complete original caller IL")
        token=int(c["callee_token"],16);needle=bytes([0x6f])+struct.pack("<I",token)
        sites=[i for i in range(len(body)-4) if body[i:i+5]==needle]
        ck(sites==c["call_sites"],"exact original callvirt sites")
        cs.extend(sites)
    ck(len(cs)==4,"all four original callers")
    return {"fact":"FACT-0304","source_original_dll":"PASS","methods":results,"direct_caller_sites":cs,"runtime_unlocked":False}
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--dll",required=True);args=parser.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_SKILL_COUNT_VALIDITY_LOOKUPS_V1",["DLL-001"]),"source witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True))
        print("PROVE_SKILL_INFO_MANAGER_SKILL_COUNT_VALIDITY_SOURCE: PASS")
        return 0
    except Exception as e:
        print("PROVE_SKILL_INFO_MANAGER_SKILL_COUNT_VALIDITY_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
