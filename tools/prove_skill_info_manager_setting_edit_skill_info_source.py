#!/usr/bin/env python3
"""FACT-0310: original 93-byte SettingEditSkillInfo and caller source gate."""
import argparse, hashlib, json, struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_setting_edit_skill_info_source.summary.json"
def ck(condition,message):
    if not condition: raise AssertionError(message)
def verify(path,w):
    pe=Path(path).read_bytes(); m=w["method"]; dll=w["dll"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(dll["size_bytes"],dll["sha256"]),"matching original retail DLL identity")
    ss,q=p.secs(pe); st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos); sb=st["#Strings"][0]; bb=st["#Blob"][0]
    fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16)); il=md[9]
    ck((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original MethodDef metadata")
    ck(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"exact original method header")
    ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"complete original 93-byte IL")
    ck(not m["has_exception_section"] and (struct.unpack_from("<H",pe,p.off(ss,md[1]))[0]&8)==0,"method has no exception section")
    for f in w["fields"]:
        token=int(f["token"],16)
        ck(p.field(pe,s,b,z,o,sb,bb,fm,token)==(f["row"],(f["owner"],""),f["name"],f["signature"]),"original field "+f["name"])
        for site in f["sites"]:
            expected=bytes([0x7e if f["opcode"]=="ldsfld" else 0x7b])+struct.pack("<I",token)
            ck(il[site:site+5]==expected,"original field site "+str(site))
    for x in w["memberrefs"]:
        token=int(x["token"],16); at=o[10]+((token&0xffffff)-1)*z[10]; raw=pe[at:at+z[10]]
        coded,at=p.rd(pe,at,z[10]-s-b); ni,at=p.rd(pe,at,s); bi,at=p.rd(pe,at,b)
        ck((raw.hex(),coded,p.s_at(pe,sb,ni),p.blob(pe,bb,bi).hex())==(x["row"],x["class_coded"],x["name"],x["signature"]),"original MemberRef "+x["token"])
        for site in x["sites"]:
            ck(il[site:site+5]==bytes([0x28 if x["opcode"]=="call" else 0x6f])+struct.pack("<I",token),"original MemberRef call site "+str(site))
    for x in w["methoddef_calls"]:
        token=int(x["token"],16)
        target=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,token); body=target[9]
        ck((target[4],target[7],len(body),hashlib.sha256(body).hexdigest())==(x["name"],(x["owner"],""),x["size"],x["sha"]),"complete source callee "+x["name"])
        for site in x["sites"]:
            ck(il[site:site+5]==b"\x6f"+struct.pack("<I",token),"original MethodDef callvirt site "+str(site))
    for x in w["branches"]:
        site=x["site"];delta=struct.unpack_from("<i",il,site+1)[0]
        ck((il[site],delta,site+5+delta)==(int(x["opcode"],16),x["relative"],x["target"]),"original branch "+str(site))
    ck(il[16:18]==bytes.fromhex("160a") and il[72:76]==bytes.fromhex("0617580a") and il[92:]==b"\x2a","original loop initialization, increment and return")
    ck(il[55]==0x6f and il[67]==0x6f and il[87]==0x3f,"original Add ordering and loop condition")
    for x in w["direct_callers"]:
        token=int(x["token"],16);md2=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,token); body=md2[9]
        ck((md2[4],md2[7],len(body),hashlib.sha256(body).hexdigest())==(x["name"],(x["owner"],""),x["size"],x["sha"]),"original full caller IL")
        pat=b"\x6f"+struct.pack("<I",int(m["token"],16))
        sites=[i for i in range(len(body)-4) if body[i:i+5]==pat]
        ck(sites==x["sites"],"original direct caller sites")
    return {"fact":"FACT-0310","original_dll_source":"PASS","complete_il_sha256":m["body_sha256"],"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_SETTING_EDIT_SKILL_INFO_SOURCE_V1",["DLL-001"]),"source witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True))
        print("PROVE_SKILL_INFO_MANAGER_SETTING_EDIT_SKILL_INFO_SOURCE: PASS")
        return 0
    except Exception as ex:
        print("PROVE_SKILL_INFO_MANAGER_SETTING_EDIT_SKILL_INFO_SOURCE: FAIL",str(ex)); return 1
if __name__=="__main__":raise SystemExit(main())
