#!/usr/bin/env python3
"""FACT-0307 source-only proof: original ParseOnOffStr and retail caller."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_on_off_str_source.summary.json"
def ck(ok,label):
    if not ok:raise AssertionError(label)
def verify(path,w):
    pe=Path(path).read_bytes();d=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original DLL identity")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos)
    sb=st["#Strings"][0];bb=st["#Blob"][0]
    _,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    v=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16))
    body=v[9]
    ck((v[0],v[1],v[4],v[5],v[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"MethodDef metadata")
    ck(pe[p.off(ss,v[1]):v[8]].hex()==m["header"],"original fat header")
    ck((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"complete 67-byte IL")
    for ref in w["memberrefs"]:
        t=int(ref["token"],16);at=o[10]+((t&0xffffff)-1)*z[10];raw=pe[at:at+z[10]]
        cls,at=p.rd(pe,at,z[10]-s-b);ni,at=p.rd(pe,at,s);si,at=p.rd(pe,at,b)
        ck((raw.hex(),cls,p.s_at(pe,sb,ni),p.blob(pe,bb,si).hex())==(ref["row"],ref["class_coded"],ref["name"],ref["signature"]),"MemberRef metadata")
        op=0x28 if ref["opcode"]=="call" else 0x6f
        for site in ref["sites"]:
            ck(body[site:site+5]==bytes([op])+struct.pack("<I",t),"original source member call")
    for lit in w["literals"]:
        tok=int(lit["token"],16);site=lit["ldstr_site"]
        ck(body[site:site+5]==bytes([0x72])+struct.pack("<I",tok),"literal IL token "+lit["text"])
        at=st["#US"][0]+(tok&0xffffff)
        raw=bytes.fromhex(lit["heap_record_hex"])
        ck(pe[at:at+len(raw)]==raw and raw[1:-1].decode("utf-16le")==lit["text"],"original user string "+lit["text"])
        ck(lit["equals_site"]==site+5 and body[lit["equals_site"]]==0x6f,"literal.Equals call site")
        ret=lit["return_site"]
        ck(body[ret:ret+2]==bytes([0x16+lit["return_ordinal"],0x2a]),"return ordinal "+lit["text"])
    for br in w["branches"]:
        at=br["site"];delta=struct.unpack_from("<i",body,at+1)[0]
        ck((body[at],delta,at+5+delta)==(int(br["opcode"],16),br["relative"],br["target"]),"original branch "+br["source"])
    for key in ["null_or_empty","default"]:
        ret=w["returns"][key];site=ret["site"]
        ck(body[site:site+2].hex()==ret["hex"] and ret["value"]==0,"original zero return")
    c=w["caller"];parent=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(c["token"],16))
    cb=parent[9];ck((parent[4],parent[7])==(c["name"],(c["owner"],"")),"original caller metadata")
    ck((len(cb),hashlib.sha256(cb).hexdigest())==(c["body_length"],c["body_sha256"]),"original caller complete IL")
    pattern=bytes([0x28])+struct.pack("<I",int(m["token"],16))
    sites=[i for i in range(len(cb)-4) if cb[i:i+5]==pattern]
    ck(sites==c["call_sites"]==[206] and c["opcode"]=="call","original direct call sites")
    return {"fact":"FACT-0307","original_source":"PASS","full_body_sha256":m["body_sha256"],"literal_results":{x["text"]:x["return_ordinal"] for x in w["literals"]},"parent_calls":sites,"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_ON_OFF_STR_SOURCE_V1",["DLL-001"]),"source witness")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_PARSE_ON_OFF_STR_SOURCE: PASS")
        return 0
    except Exception as e:
        print("PROVE_SKILL_INFO_MANAGER_PARSE_ON_OFF_STR_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
