#!/usr/bin/env python3
"""FACT-0305: original DLL-only GetReversalSkillInfo byte and caller proof."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_get_reversal_skill_info_source.summary.json"
def ck(cond,msg):
    if not cond: raise AssertionError(msg)
def verify(dll_path,w):
    pe=Path(dll_path).read_bytes();d=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original DLL identity")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos)
    sb=st["#Strings"][0];bb=st["#Blob"][0]
    field_owners,method_owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    node=p.method(pe,ss,s,b,ix,z,o,sb,bb,method_owners,int(m["token"],16));body=node[9]
    ck((node[0],node[1],node[4],node[5],node[7])==(m["metadata_row_hex"],int(m["rva"],16),m["name"],m["signature_hex"],(m["owner"],"")),"MethodDef row/owner/signature")
    ck(pe[p.off(ss,node[1]):node[8]].hex()==m["header_hex"]=="82","original tiny header")
    ck((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["il_hex"],m["code_sha256"]),"complete original 32-byte IL")
    f=w["field"]
    ck(p.field(pe,s,b,z,o,sb,bb,field_owners,int(f["token"],16))==(f["metadata_row_hex"],(f["owner"],""),f["name"],f["signature_hex"]),"original FieldDef metadata")
    ck(body[f["ldfld_il"]:f["ldfld_il"]+5]==bytes([0x7b])+struct.pack("<I",int(f["token"],16)),"original reversal field load")
    ref=w["memberref"];t=int(ref["token"],16);at=o[10]+((t&0xffffff)-1)*z[10];row=pe[at:at+z[10]]
    coded,at=p.rd(pe,at,z[10]-s-b);ni,at=p.rd(pe,at,s);bi,at=p.rd(pe,at,b)
    ck((row.hex(),coded,p.s_at(pe,sb,ni),p.blob(pe,bb,bi).hex())==(ref["metadata_row_hex"],ref["class_coded"],ref["name"],ref["signature_hex"]),"original MemberRef get_Item")
    ck(body[ref["callvirt_il"]:ref["callvirt_il"]+5]==bytes([0x6f])+struct.pack("<I",t),"original get_Item callvirt")
    bound=w["bounds"]
    ck((bound["lower"],bound["upper"],bound["negative_null_site"],bound["above_null_site"],bound["lookup_site"])==(0,121,7,17,19),"numeric bounds and sites")
    ck(body[0:2]==bytes([0x03,0x16]) and body[9:12]==bytes([0x03,0x1f,0x79]),"original numeric guard operands")
    for branch in bound["branches"]:
        i=branch["il"];rel=struct.unpack_from("<i",body,i+1)[0]
        ck((body[i],rel,i+5+rel)==(int(branch["opcode"],16),branch["relative"],branch["target"]),"original bound branch "+branch["guard"])
    for site in [bound["negative_null_site"],bound["above_null_site"]]:
        ck(body[site:site+2].hex()==bound["null_il"],"original null return")
    ck(body[bound["lookup_site"]:].hex()==bound["lookup_hex"],"original lookup and return")
    observed=[]
    for caller in w["direct_callers"]:
        parent=p.method(pe,ss,s,b,ix,z,o,sb,bb,method_owners,int(caller["token"],16))
        ck((parent[4],parent[7])==(caller["name"],(caller["owner"],"")),"original caller metadata")
        code=parent[9]
        ck((len(code),hashlib.sha256(code).hexdigest())==(caller["body_bytes"],caller["body_sha256"]),"full original caller IL")
        needle=bytes([0x6f])+struct.pack("<I",int(m["token"],16))
        sites=[i for i in range(len(code)-4) if code[i:i+5]==needle]
        ck(sites==caller["sites"] and caller["opcode"]=="callvirt","original caller sites "+caller["name"])
        observed.extend((caller["token"],a) for a in sites)
    ck(len(observed)==5,"source exact caller count")
    return {"fact_id":"FACT-0305","original_source":"PASS","method_sha256":m["code_sha256"],"direct_call_sites":observed,"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_GET_REVERSAL_SKILL_INFO_SOURCE_V1",["DLL-001"]),"source witness")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_GET_REVERSAL_SKILL_INFO: PASS")
        return 0
    except Exception as exc:
        print("PROVE_SKILL_INFO_MANAGER_GET_REVERSAL_SKILL_INFO: FAIL",str(exc));return 1
if __name__=="__main__":raise SystemExit(main())
