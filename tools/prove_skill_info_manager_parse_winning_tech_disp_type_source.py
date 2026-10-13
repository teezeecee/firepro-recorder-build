#!/usr/bin/env python3
"""FACT-0301: original DLL proof for the WinningTechDispType parser."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_winning_tech_disp_type_source.summary.json"
def check(value,label):
    if not value: raise AssertionError(label)
def verify(path,w):
    pe=Path(path).read_bytes(); d=w["dll"];m=w["method"]
    check((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"original DLL identity")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos)
    sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    node=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16))
    body=node[9]
    check((node[0],node[1],node[4],node[5],node[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original MethodDef identity")
    check(pe[p.off(ss,node[1]):node[8]].hex()==m["header"],"original fat header")
    check((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"entire original 71-byte IL")
    for x in w["memberrefs"]:
        t=int(x["token"],16);a=x["site"];op=0x28 if x["opcode"]=="call" else 0x6f
        check(body[a:a+5]==bytes([op])+struct.pack("<I",t),"original call instruction "+str(a))
        loc=o[10]+((t&0xffffff)-1)*z[10];rec=pe[loc:loc+z[10]]
        coded,at=p.rd(pe,loc,z[10]-s-b);ni,at=p.rd(pe,at,s);si,at=p.rd(pe,at,b)
        check((rec.hex(),p.s_at(pe,sb,ni),p.blob(pe,bb,si).hex())==(x["row"],x["name"],x["signature"]),"original MemberRef "+x["name"])
    for x in w["substring_windows"]:
        a=x["call_site"];check(body[a-3:a+5].hex()==x["hex"],"source Substring arguments "+str(a))
    literal=w["literal"];token=int(literal["token"],16);a=literal["site"]
    check(body[a:a+5]==bytes([0x72])+struct.pack("<I",token),"original space ldstr token")
    us=st["#US"][0]+(token&0xffffff)
    check(pe[us:us+4].hex()==literal["heap_bytes"] and pe[us+1:us+3].decode("utf-16le")==literal["value"],"original space heap")
    for x in w["branches"]:
        a=x["site"];rel=struct.unpack_from("<i",body,a+1)[0]
        check((body[a],rel,a+5+rel)==(int(x["opcode"],16),x["relative"],x["target"]),"original branch/leave "+str(a))
    for key,sitekey in (("empty_il","empty_site"),("format_mismatch_il","format_mismatch_site"),("catch_il","catch_site"),("normal_il","normal_site")):
        x=w["returns"];frag=bytes.fromhex(x[key]);a=x[sitekey]
        check(body[a:a+len(frag)]==frag,"original return sequence "+key)
    e=w["exception"];loc=(node[8]+len(body)+3)&~3;data=pe[loc:loc+16]
    check(data.hex()==e["hex"],"original small exception bytes")
    check((data[0],data[1],struct.unpack_from("<H",data,4)[0],struct.unpack_from("<H",data,6)[0],data[8],struct.unpack_from("<H",data,9)[0],data[11],struct.unpack_from("<I",data,12)[0])==(1,16,0,e["try_offset"],e["try_length"],e["handler_offset"],e["handler_length"],int(e["catch_type"],16)),"original EH clause shape and bounds")
    check(w["substring_windows"][0]["call_site"] < e["try_offset"] and e["try_offset"]==40,"first substring outside catch")
    t=int(e["catch_type"],16);a=o[1]+((t&0xffffff)-1)*z[1];rec=pe[a:a+z[1]]
    coded,a=p.rd(pe,a,z[1]-2*s);ni,a=p.rd(pe,a,s);ns,a=p.rd(pe,a,s)
    check((rec.hex(),p.s_at(pe,sb,ni),p.s_at(pe,sb,ns))==(e["catch_typeref_row"],e["catch_name"],e["catch_namespace"]),"original catch TypeRef")
    par=w["parent"];caller=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(par["token"],16));cb=caller[9]
    check((len(cb),hashlib.sha256(cb).hexdigest())==(par["body_length"],par["body_sha256"]),"original parent full IL identity")
    pat=b"\x28"+struct.pack("<I",int(m["token"],16))
    sites=[i for i in range(len(cb)-4) if cb[i:i+5]==pat]
    check(sites==par["direct_call_sites"]==[262],"one original parent call site")
    return {"fact":"FACT-0301","source_original_dll":"PASS","substring_windows":[[x["start"],x["length"]] for x in w["substring_windows"]],"direct_parent_calls":sites,"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        check((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_WINNING_TECH_DISP_TYPE_SOURCE_V1",["DLL-001"]),"witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_WINNING_TECH_DISP_TYPE_SOURCE: PASS")
        return 0
    except Exception as ex:
        print("PROVE_WINNING_TECH_DISP_TYPE_SOURCE: FAIL",str(ex));return 1
if __name__=="__main__":raise SystemExit(main())
