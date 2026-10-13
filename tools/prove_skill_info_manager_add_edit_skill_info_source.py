#!/usr/bin/env python3
"""FACT-0308: original DLL-only 26-byte AddEditSkillInfo and direct caller proof."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_add_edit_skill_info_source.summary.json"
def ck(ok,label):
    if not ok: raise AssertionError(label)
def verify(dll_path,w):
    pe=Path(dll_path).read_bytes();d=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original retail DLL SHA")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos)
    sb=st["#Strings"][0];bb=st["#Blob"][0]
    fieldowners,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    node=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));body=node[9]
    ck((node[0],node[1],node[4],node[5],node[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original MethodDef metadata")
    ck(pe[p.off(ss,node[1]):node[8]].hex()==m["header"]=="6a","original tiny method header")
    ck((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["code_bytes"],m["body_hex"],m["code_sha256"]),"full original 26-byte IL identity")
    for f in w["fields"]:
        t=int(f["token"],16)
        ck(p.field(pe,s,b,z,o,sb,bb,fieldowners,t)==(f["row"],(f["owner"],""),f["name"],f["signature"]),"original FieldDef "+f["name"])
        ck(body[f["site"]:f["site"]+5]==bytes([0x7b])+struct.pack("<I",t),"original ldfld "+f["name"])
    for r in w["memberrefs"]:
        t=int(r["token"],16);at=o[10]+((t&0xffffff)-1)*z[10];raw=pe[at:at+z[10]]
        cls,at=p.rd(pe,at,z[10]-s-b);ni,at=p.rd(pe,at,s);si,at=p.rd(pe,at,b)
        ck((raw.hex(),cls,p.s_at(pe,sb,ni),p.blob(pe,bb,si).hex())==(r["row"],r["class_coded"],r["name"],r["signature"]),"original MemberRef "+r["token"])
        ck(body[r["site"]:r["site"]+5]==bytes([0x6f])+struct.pack("<I",t),"original Add callvirt "+str(r["site"]))
    f=w["method_flow"]
    ck((f["first_arg_id_site"],f["first_arg_data_site"],f["second_arg_id_site"],f["return_site"])==(6,7,19,25),"original argument positions")
    ck(body[6:8]==bytes([0x04,0x03]) and body[19]==0x04 and body[25]==0x2a,"original argument opcodes and ret")
    ck(f["method_has_exception_section"] is False and int(m["header"],16)&3==2,"tiny method has no EH")
    calls=[]
    for c in w["direct_callers"]:
        node=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(c["token"],16))
        code=node[9]
        ck((node[4],node[7])==(c["name"],(c["owner"],"")),"original caller metadata")
        ck((len(code),hashlib.sha256(code).hexdigest())==(c["body_bytes"],c["body_sha256"]),"full original caller IL "+c["name"])
        pattern=bytes([0x6f])+struct.pack("<I",int(m["token"],16))
        sites=[i for i in range(len(code)-4) if code[i:i+5]==pattern]
        ck(c["opcode"]=="callvirt" and sites==c["sites"],"original caller sites "+c["name"])
        calls.extend((c["token"],site) for site in sites)
    ck(len(calls)==3,"three original direct sites")
    return {"fact":"FACT-0308","original_dll_source":"PASS","method_sha256":m["code_sha256"],"call_sites":calls,"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_ADD_EDIT_SKILL_INFO_SOURCE_V1",["DLL-001"]),"witness source identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_ADD_EDIT_SKILL_INFO_SOURCE: PASS")
        return 0
    except Exception as e:
        print("PROVE_SKILL_INFO_MANAGER_ADD_EDIT_SKILL_INFO_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
