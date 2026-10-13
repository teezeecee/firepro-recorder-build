#!/usr/bin/env python3
"""FACT-0313: byte-exact DLCChecker.IsOwner and IsValidDLCID original source evidence."""
import argparse,hashlib,json,struct
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as p
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/dlc_checker_is_owner_source.summary.json"
def ck(ok,msg):
    if not ok:raise AssertionError(msg)
def verify(path,w):
    pe=Path(path).read_bytes();d=w["dll"]
    ck((len(pe),hashlib.sha256(pe).hexdigest())==(d["size_bytes"],d["sha256"]),"matching original retail DLL")
    ss,q=p.secs(pe);st,hs,rows,pos=p.mdstreams(pe,ss,q)
    s,b,ix,z,o=p.tables(pe,st,hs,rows,pos);sb=st["#Strings"][0];bb=st["#Blob"][0]
    _,owners=p.owner_maps(pe,rows,s,ix,z,o,sb)
    mdict={}
    for m in w["methods"]:
        md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(m["token"],16));il=md[9]
        ck((md[0],md[1],md[4],md[5],md[7])==(m["row"],int(m["rva"],16),m["name"],m["signature"],(m["owner"],m["namespace"])),"original MethodDef "+m["token"])
        ck(pe[p.off(ss,md[1]):md[8]].hex()==m["header"],"original method header "+m["token"])
        ck((len(il),il.hex(),hashlib.sha256(il).hexdigest())==(m["body_length"],m["body_hex"],m["body_sha256"]),"full original IL "+m["token"])
        mdict[m["token"]]=md
    cal=w["methoddef_callee"]
    md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(cal["token"],16))
    ck((md[0],md[1],md[4],md[5],md[7],len(md[9]),hashlib.sha256(md[9]).hexdigest())==(cal["row"],int(cal["rva"],16),cal["name"],cal["signature"],(cal["owner"],cal["namespace"]),cal["body_length"],cal["body_sha256"]),"original DLCID.GetDLCID callee identity")
    for ty in w["typerefs"]:
        tok=int(ty["token"],16);r=tok&0xffffff;at=o[1]+(r-1)*z[1];row=pe[at:at+z[1]]
        coded,at=p.rd(pe,at,z[1]-2*s);ni,at=p.rd(pe,at,s);nsi,at=p.rd(pe,at,s)
        ck((row.hex(),coded,p.s_at(pe,sb,ni),p.s_at(pe,sb,nsi))==(ty["row"],ty["resolution_scope_coded"],ty["name"],ty["namespace"]),"original TypeRef "+ty["token"])
    for mr in w["memberrefs"]:
        tok=int(mr["token"],16);at=o[10]+((tok&0xffffff)-1)*z[10];row=pe[at:at+z[10]]
        coded,at=p.rd(pe,at,z[10]-s-b);ni,at=p.rd(pe,at,s);bi,at=p.rd(pe,at,b)
        ck((row.hex(),coded,p.s_at(pe,sb,ni),p.blob(pe,bb,bi).hex())==(mr["row"],mr["class_coded"],mr["name"],mr["signature"]),"original MemberRef "+mr["token"])
        # MemberRefParent coded tag 1 means TypeRef; check exact type token from raw metadata.
        ck((coded&7)==1 and (0x01000000|(coded>>3))==int(mr["owner_type_token"],16),"original MemberRef owner")
        for site in mr["sites"]:
            il=mdict[site["method"]][9];offset=site["offset"]
            ck(il[offset:offset+5]==bytes([int(site["opcode"],16)])+struct.pack("<I",tok),"original MemberRef call site "+mr["token"])
    for call in w["methoddef_call_sites"]:
        il=mdict[call["method"]][9];pos=call["offset"]
        ck(il[pos:pos+5]==bytes([int(call["opcode"],16)])+struct.pack("<I",int(call["target"],16)),"original MethodDef direct call at "+str(pos))
    eh=w["exception_section"];src=mdict[eh["method"]];rva=src[1];il=src[9]
    # CLR method with MoreSects: exception table is 4-byte aligned following full IL.
    start=p.off(ss,rva);data_end=src[8]+len(il);sect=(data_end+3)&~3
    clause=pe[sect:sect+16];c=eh["clause"]
    ck(clause.hex()==eh["raw_hex"],"original complete EH bytes")
    flags,tryoff,trylen,handleroff,handlerlen,token=struct.unpack_from("<HHBHB I",clause,4)
    ck((flags,tryoff,trylen,handleroff,handlerlen,token)==(c["flags"],c["try_offset"],c["try_length"],c["handler_offset"],c["handler_length"],int(c["class_token"],16)),"original exception clause interval")
    ck((c["try_offset"],c["try_offset"]+c["try_length"])==(15,29),"handler covers subscription call, not AppId_t constructor")
    for entry in w["leave_instructions"]:
        il=mdict[entry["method"]][9];i=entry["offset"];delta=struct.unpack_from("<i",il,i+1)[0]
        ck((il[i],delta,i+5+delta)==(int(entry["opcode"],16),entry["delta"],entry["target"]),"original leave target")
    for caller in w["direct_callers"]:
        md=p.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(caller["caller"],16));il=md[9]
        ck((md[4],md[7],len(il),hashlib.sha256(il).hexdigest())==(caller["name"],(caller["owner"],caller["namespace"]),caller["size"],caller["sha"]),"original full caller "+caller["caller"])
        for entry in caller["callees"]:
            pat=bytes([int(entry["opcode"],16)])+struct.pack("<I",int(entry["target"],16))
            ck([i for i in range(len(il)-4) if il[i:i+5]==pat]==entry["sites"],"original call site "+caller["caller"])
    return {"fact":"FACT-0313","original_dll_source":"PASS","method_count":len(w["methods"]),"pinned_caller_count":len(w["direct_callers"]),"runtime_eligible":False}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);args=ap.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        ck((w["dataset_id"],w["source_ids"])==("DLL_DLC_CHECKER_IS_OWNER_SOURCE_V1",["DLL-001"]),"witness identity")
        print(json.dumps(verify(args.dll,w),sort_keys=True));print("PROVE_DLC_CHECKER_IS_OWNER_SOURCE: PASS");return 0
    except Exception as e:
        print("PROVE_DLC_CHECKER_IS_OWNER_SOURCE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
