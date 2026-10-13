#!/usr/bin/env python3
"""FACT-0309: byte-exact original DeleteEditSkillInfo IL, metadata and callers."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_delete_edit_skill_info_source.summary.json"
def ck(x,msg):
    if not x: raise AssertionError(msg)
def verify(path,w):
    pe=Path(path).read_bytes();dll=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(dll["size_bytes"],dll["sha256"]),"original SHA-matched retail DLL")
    ss,q=p.secs(pe);streams,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,streams,hs,rows,pos)
    sb=streams["#Strings"][0];bb=streams["#Blob"][0]
    fowners,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=md[9]
    ck((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original MethodDef metadata")
    ck(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"original fat header")
    ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"complete exact original IL")
    ck((struct.unpack_from("<H",pe,p.off(ss,md[1]))[0]&8)==0 and not m["has_exception_section"],"no exception section in original fat header")
    for f in w["fields"]:
        tok=int(f["token"],16)
        ck(p.field(pe,s,b,z,o,sb,bb,fowners,tok)==(f["row"],(f["owner"],""),f["name"],f["signature"]),"source FieldDef "+f["name"])
        for site in f["sites"]:
            ck(il[site:site+5]==bytes([0x7b])+struct.pack("<I",tok),"original ldfld "+str(site))
    for ref in w["memberrefs"]:
        tok=int(ref["token"],16);at=o[10]+((tok&0xffffff)-1)*z[10];row=pe[at:at+z[10]]
        coded,at=p.rd(pe,at,z[10]-s-b);ni,at=p.rd(pe,at,s);bi,at=p.rd(pe,at,b)
        ck((row.hex(),coded,p.s_at(pe,sb,ni),p.blob(pe,bb,bi).hex())==(ref["row"],ref["class_coded"],ref["name"],ref["signature"]),"source MemberRef "+ref["token"])
        for site in ref["sites"]:
            ck(il[site:site+5]==bytes([0x6f])+struct.pack("<I",tok),"original callvirt "+str(site))
    for br in w["branches"]:
        site=br["site"];delta=struct.unpack_from("<i",il,site+1)[0]
        ck((il[site],delta,site+5+delta)==(int(br["opcode"],16),br["relative"],br["target"]),"original branch "+str(site))
    flow=w["semantics"]
    ck(il[:2]==bytes.fromhex("160a") and il[flow["compare_argument_site"]]==0x03,"initial index, comparison arg")
    ck(il[42:46]==bytes.fromhex("0617580a") and il[flow["discard_remove_boolean_site"]:]==bytes.fromhex("262a"),"index increment and Boolean pop+ret")
    ck(flow["remove_list_site"]==32 and flow["contains_key_site"]==70 and flow["remove_dictionary_site"]==87,"original source operation sites")
    sites_all=[]
    for parent in w["direct_callers"]:
        node=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(parent["token"],16));body=node[9]
        ck((node[4],node[7])==(parent["name"],(parent["owner"],"")),"source caller metadata")
        ck((len(body),hashlib.sha256(body).hexdigest())==(parent["size"],parent["sha"]),"complete source caller IL "+parent["name"])
        pattern=bytes([0x6f])+struct.pack("<I",int(m["token"],16))
        sites=[i for i in range(len(body)-4) if body[i:i+5]==pattern]
        ck(sites==parent["sites"],"source direct caller site "+parent["name"])
        sites_all.extend(sites)
    ck(len(sites_all)==5,"five original direct callers")
    return {"fact":"FACT-0309","original_dll_source":"PASS","complete_il_sha256":m["body_sha256"],"caller_sites":sites_all,"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_DELETE_EDIT_SKILL_INFO_SOURCE_V1",["DLL-001"]),"source witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_SKILL_INFO_MANAGER_DELETE_EDIT_SKILL_INFO_SOURCE: PASS")
        return 0
    except Exception as ex:
        print("PROVE_SKILL_INFO_MANAGER_DELETE_EDIT_SKILL_INFO_SOURCE: FAIL",str(ex));return 1
if __name__=="__main__":raise SystemExit(main())
