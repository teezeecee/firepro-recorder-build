#!/usr/bin/env python3
"""FACT-0311: exact original SkillInfo DLC flag source, 4 methods and callers."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_dlc_flag_source.summary.json"
def ck(value,msg):
    if not value:raise AssertionError(msg)
def verify(path,w):
    pe=Path(path).read_bytes();dll=w["dll"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(dll["size_bytes"],dll["sha256"]),"original DLL identity")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q);s,b,ix,z,o=p.tables(pe,st,hs,rows,pos)
    sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    fdict={f["token"]:f for f in w["fields"]}
    for f in w["fields"]:
        tok=int(f["token"],16)
        ck(p.field(pe,s,b,z,o,sb,bb,fm,tok)==(f["row"],(f["owner"],""),f["name"],f["signature"]),"original field "+f["token"])
    zref={x["token"]:x for x in w["memberrefs"]}
    for ref in w["memberrefs"]:
        tok=int(ref["token"],16);at=o[10]+((tok&0xffffff)-1)*z[10];raw=pe[at:at+z[10]]
        coded,at=p.rd(pe,at,z[10]-s-b);ni,at=p.rd(pe,at,s);bi,at=p.rd(pe,at,b)
        ck((raw.hex(),coded,p.s_at(pe,sb,ni),p.blob(pe,bb,bi).hex())==(ref["row"],ref["class_coded"],ref["name"],ref["signature"]),"original MemberRef "+ref["token"])
    target=w["methoddef_callee"];node=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(target["token"],16))
    ck((node[0],node[4],node[5],node[7])==(target["row"],target["name"],target["signature"],(target["owner"],"")),"IsDLCInstalled source callee identity")
    for m in w["methods"]:
        md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=md[9]
        ck((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original MethodDef "+m["token"])
        ck(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"original header "+m["token"])
        ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"original complete method IL "+m["token"])
        for site in m["flags_sites"]:
            ck(il[site:site+5]==b"\x7b"+struct.pack("<I",int("0x04000ED4",16)),"original DLC field site")
        for site in m["static_sites"]:
            ck(il[site:site+5]==b"\x7e"+struct.pack("<I",int("0x040064EC",16)),"original static inst field site")
        for site,opcode,dest in m["branches"]:
            delta=struct.unpack_from("<i",il,site+1)[0]
            ck((il[site],site+5+delta)==(opcode,dest),"original branch target "+m["token"]+":"+str(site))
        for c in m["methoddef_sites"]:
            ck(il[c["site"]:c["site"]+5]==bytes([0x28 if c["site"]==1 else 0x6f])+struct.pack("<I",int(c["token"],16)),"original callee site")
        for x in m.get("memberref_sites",[]):
            ck(il[x["site"]:x["site"]+5]==bytes([int(x["opcode"],16)])+struct.pack("<I",int(x["token"],16)),"original memberref site")
    by_name={x["name"]:bytes.fromhex(x["body_hex"]) for x in w["methods"]}
    ck(by_name["IsDLCMove"][27:29]==bytes.fromhex("1f10") and by_name["GetDLC"][27:29]==bytes.fromhex("1f0d"),"distinct original 16 and 13 loop bounds")
    ck(by_name["GetDLCList"][50:52]==bytes.fromhex("1f0d") and by_name["CheckValidationDLCMove"][56:58]==bytes.fromhex("1f0d"),"original list and validation bounds")
    for x in w["direct_callers"]:
        md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(x["caller"],16));il=md[9]
        ck((md[4],md[7],len(il),hashlib.sha256(il).hexdigest())==(x["name"],(x["owner"],""),x["size"],x["sha"]),"original full caller "+x["caller"])
        pat=bytes([int(x["opcode"],16)])+struct.pack("<I",int(x["callee"],16))
        sites=[i for i in range(len(il)-4) if il[i:i+5]==pat]
        ck(sites==x["sites"],"original direct caller site "+x["caller"])
    return {"fact":"FACT-0311","original_dll_source":"PASS","method_count":len(w["methods"]),"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_DLC_FLAG_SOURCE_V1",["DLL-001"]),"source witness ID")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_SKILL_INFO_DLC_FLAG_SOURCE: PASS");return 0
    except Exception as e:
        print("PROVE_SKILL_INFO_DLC_FLAG_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
