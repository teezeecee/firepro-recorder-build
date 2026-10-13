#!/usr/bin/env python3
"""FACT-0303: source-only proof of two distinct retail method rows sharing exact IL."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_cheer_art_literal_pair_source.summary.json"
def ck(ok,label):
    if not ok: raise AssertionError(label)
def verify(dllpath,w):
    raw=Path(dllpath).read_bytes();d=w["dll"]
    ck(len(raw)==d["size_bytes"] and hashlib.sha256(raw).hexdigest()==d["sha256"],"original DLL byte identity")
    ss,q=p.secs(raw);streams,hs,rows,pos=p.mdstreams(raw,ss,q)
    s,b,ix,z,o=p.tables(raw,streams,hs,rows,pos)
    strings=streams["#Strings"][0];blobs=streams["#Blob"][0]
    _,owners=p.owner_maps(raw,rows,s,ix,z,o,strings)
    shared=w["shared_body"];expected=bytes.fromhex(shared["body_hex"])
    ck(len(expected)==shared["body_length"]==123 and hashlib.sha256(expected).hexdigest()==shared["body_sha256"],"full witness IL")
    parent=w["parent"]
    caller=p.method(raw,ss,s,b,ix,z,o,strings,blobs,owners,int(parent["token"],16))
    cb=caller[9]
    ck(len(cb)==parent["body_length"] and hashlib.sha256(cb).hexdigest()==parent["body_sha256"],"exact original parent full IL")
    calls=[]
    for m in w["methods"]:
        token=int(m["token"],16)
        v=p.method(raw,ss,s,b,ix,z,o,strings,blobs,owners,token)
        ck((v[0],v[1],v[4],v[5],v[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"distinct MethodDef metadata "+m["name"])
        ck(raw[p.off(ss,v[1]):v[8]].hex()==shared["header"],"original fat header "+m["name"])
        ck(v[9]==expected,"complete original matching IL "+m["name"])
        flags=struct.unpack_from("<H",raw,p.off(ss,v[1]))[0]
        ck(flags&8==0 and shared["has_exception_section"] is False,"no exception section "+m["name"])
        body=v[9]
        for mr in w["memberrefs"]:
            t=int(mr["token"],16);op=0x28 if mr["opcode"]=="call" else 0x6f
            at=o[10]+((t&0xffffff)-1)*z[10];record=raw[at:at+z[10]]
            coded,at=p.rd(raw,at,z[10]-s-b);ni,at=p.rd(raw,at,s);bi,at=p.rd(raw,at,b)
            ck((record.hex(),p.s_at(raw,strings,ni),p.blob(raw,blobs,bi).hex())==(mr["row"],mr["name"],mr["signature"]),"original MemberRef metadata")
            for site in mr["sites"]:
                ck(body[site:site+5]==bytes([op])+struct.pack("<I",t),"original call "+str(site))
        empty=w["empty_check"]
        ck(body[empty["call_site"]]==0x28 and body[empty["branch_site"]]==0x39,"empty check source instructions")
        rel=struct.unpack_from("<i",body,empty["branch_site"]+1)[0]
        ck(empty["branch_site"]+5+rel==empty["false_target"] and body[empty["return_site"]:empty["return_site"]+2].hex()==empty["return_hex"],"empty -> zero")
        for c in w["literal_cases"]:
            site=c["ldstr_site"];t=int(c["token"],16)
            ck(body[site:site+5]==bytes([0x72])+struct.pack("<I",t),"original literal token "+c["literal"])
            us=streams["#US"][0]+(t&0xffffff)
            ck(raw[us:us+4].hex()==c["heap_record"] and raw[us+1:us+3].decode("utf-16le")==c["literal"],"original literal heap "+c["literal"])
            ck(c["equals_site"]==site+5 and body[c["equals_site"]:c["equals_site"]+5]==bytes([0x6f])+struct.pack("<I",0x0A00030C),"original String.Equals "+c["literal"])
            bs=c["branch_site"]
            ck(body[bs]==0x39 and bs+5+struct.unpack_from("<i",body,bs+1)[0]==c["false_target"],"original conditional branch "+c["literal"])
            expectret=bytes([0x16+c["return_ordinal"],0x2a])
            ck(body[c["return_site"]:c["return_site"]+2]==expectret,"original numeric ordinal "+c["literal"])
        dr=w["default_return"]
        ck(body[dr["site"]:dr["site"]+2]==bytes.fromhex(dr["hex"]) and dr["ordinal"]==0,"unmatched returns 0")
        needle=bytes([0x28])+struct.pack("<I",token)
        sites=[i for i in range(len(cb)-4) if cb[i:i+5]==needle]
        ck(sites==m["parent_call_sites"],"original ParseSkillParam call "+m["name"])
        calls.extend(sites)
    ck(sorted(calls)==[1179,1197],"two unique source parent calls")
    return {"fact":"FACT-0303","original_dll_source":"PASS","method_count":2,"literal_to_ordinals":{x["literal"]:x["return_ordinal"] for x in w["literal_cases"]},"parent_calls":sorted(calls),"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_CHEER_ART_LITERAL_PAIR_SOURCE_V1",["DLL-001"]),"witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True))
        print("PROVE_SKILL_INFO_MANAGER_CHEER_ART_LITERAL_PAIR_SOURCE: PASS")
        return 0
    except Exception as e:
        print("PROVE_SKILL_INFO_MANAGER_CHEER_ART_LITERAL_PAIR_SOURCE: FAIL",str(e))
        return 1
if __name__=="__main__":raise SystemExit(main())
