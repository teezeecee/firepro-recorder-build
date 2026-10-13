#!/usr/bin/env python3
"""FACT-0302: original retail DLL-only proof of Parse_FilteringType."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_filtering_type_source.summary.json"
def ck(cond,label):
    if not cond: raise AssertionError(label)
def verify(path,w):
    pe=Path(path).read_bytes();d=w["dll"];m=w["method"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"retail DLL SHA identity")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos)
    sb=st["#Strings"][0];bb=st["#Blob"][0]
    fm,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    node=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16))
    body=node[9]
    ck((node[0],node[1],node[4],node[5],node[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],"")),"original MethodDef metadata")
    ck(pe[p.off(ss,node[1]):node[8]].hex()==m["header"],"fat header")
    ck((len(body),body.hex(),hashlib.sha256(body).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"full 74-byte original IL")
    for x in w["memberrefs"]:
        t=int(x["token"],16);a=x["site"];opcode=0x28 if x["opcode"]=="call" else 0x6f
        ck(body[a:a+5]==bytes([opcode])+struct.pack("<I",t),"call instruction "+str(a))
        loc=o[10]+((t&0xffffff)-1)*z[10];record=pe[loc:loc+z[10]]
        coded,at=p.rd(pe,loc,z[10]-s-b);ni,at=p.rd(pe,at,s);si,at=p.rd(pe,at,b)
        ck((record.hex(),p.s_at(pe,sb,ni),p.blob(pe,bb,si).hex())==(x["row"],x["name"],x["signature"]),"MemberRef "+str(a))
    for x in w["substring_windows"]:
        a=x["call_site"]
        ck(body[a-3:a+5].hex()==x["hex"],"Substring numeric arguments")
    lit=w["literal"];t=int(lit["token"],16);a=lit["site"]
    ck(body[a:a+5]==bytes([0x72])+struct.pack("<I",t),"original ldstr")
    us=st["#US"][0]+(t&0xffffff)
    ck(pe[us:us+4].hex()==lit["heap_bytes"] and pe[us+1:us+3].decode("utf-16le")==lit["value"],"original US literal space")
    for x in w["branches"]:
        a=x["site"];rel=struct.unpack_from("<i",body,a+1)[0]
        ck((body[a],rel,a+5+rel)==(int(x["opcode"],16),x["relative"],x["target"]),"branch "+str(a))
    ret=w["returns"]
    for part in ["empty","format_mismatch","catch","normal"]:
        frag=bytes.fromhex(ret[part+"_il"]);at=ret[part+"_site"]
        ck(body[at:at+len(frag)]==frag,"return "+part)
    ck(ret["fallback_ordinal"]==38 and body[11:14]==bytes([0x1f,0x26,0x2a]) and body[37:40]==bytes([0x1f,0x26,0x2a]) and body[63:67]==bytes([0x26,0x1f,0x26,0x0b]),"three fallback returns assign original 38")
    eh=w["exception"];loc=(node[8]+len(body)+3)&~3;dat=pe[loc:loc+16]
    ck(dat.hex()==eh["hex"],"original small catch section")
    ck(dat[0]==1 and dat[1]==16 and struct.unpack_from("<H",dat,6)[0]==eh["try_offset"] and dat[8]==eh["try_length"] and struct.unpack_from("<H",dat,9)[0]==eh["handler_offset"] and dat[11]==eh["handler_length"] and struct.unpack_from("<I",dat,12)[0]==int(eh["catch_type"],16),"catch bounds and token")
    ck(w["substring_windows"][0]["call_site"]<eh["try_offset"] and w["substring_windows"][1]["call_site"]>=eh["try_offset"],"first substring outside source catch")
    t=int(eh["catch_type"],16);at=o[1]+((t&0xffffff)-1)*z[1];r=pe[at:at+z[1]]
    coded,at=p.rd(pe,at,z[1]-2*s);ni,at=p.rd(pe,at,s);ns,at=p.rd(pe,at,s)
    ck((p.s_at(pe,sb,ni),p.s_at(pe,sb,ns))==(eh["catch_name"],eh["catch_namespace"]),"catch System.Object")
    par=w["parent"];n=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(par["token"],16));cb=n[9]
    ck((len(cb),hashlib.sha256(cb).hexdigest())==(par["body_length"],par["body_sha256"]),"original parent full IL")
    pattern=bytes([0x28])+struct.pack("<I",int(m["token"],16))
    sites=[i for i in range(len(cb)-4) if cb[i:i+5]==pattern]
    ck(sites==par["direct_call_sites"]==[188],"direct original parent call")
    return {"fact":"FACT-0302","source_original_dll":"PASS","parent_calls":sites,"fallback_ordinal":38,"runtime_eligible":False}
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_FILTERING_TYPE_SOURCE_V1",["DLL-001"]),"witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_FILTERING_TYPE_SOURCE: PASS")
        return 0
    except Exception as ex:
        print("PROVE_FILTERING_TYPE_SOURCE: FAIL",str(ex));return 1
if __name__=="__main__":raise SystemExit(main())
