#!/usr/bin/env python3
"""FACT-0263: original-byte source replay for overloaded MoveToDest wrapper."""
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_move_to_dest_vector_wrapper.summary.json"
T=0x06004FDB
def need(cond,msg):
    if not cond: raise RuntimeError(msg)
def verify_dll(path,w):
    pe=Path(path).read_bytes();d=w["dll"];m=d["method"]
    need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"original retail DLL identity")
    ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
    fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=md
    need((raw,rva,impl,flags,name,sig,owner)==(m["methoddef_row_hex"],int(m["rva"],16),int(m["impl_flags_raw"],16),int(m["method_attributes_raw"],16),m["name"],m["signature_blob_hex"],(m["owner"],m["namespace"])),"exact MethodDef")
    need(pe[base.off(ss,rva):start].hex()==m["tiny_header_hex"]=="56","tiny header")
    need(body.hex()==m["body_hex"]=="020f017b5900000a0f017b5a00000a28dc4f00062a","exact 21 IL bytes")
    need(len(body)==m["code_size"]==21 and hashlib.sha256(body).hexdigest()==m["code_sha256"],"code size/hash")
    nxt=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)
    need(nxt[6]==plist+1 and m["parameter_count"]==1,"exact one Param range")
    pp=o[8]+(plist-1)*z[8];param=pe[pp:pp+z[8]]
    need(param.hex()==m["parameter_row_hex"],"raw Param row")
    ni,_=base.rd(pe,pp+4,s)
    need(base.s_at(pe,sb,ni)==m["parameter_name"]=="dest","Param name")
    need(len(d["instructions"])==m["decoded_instruction_count"]==7,"decoded instruction count")
    expected=[("0x0000","ldarg.0"),("0x0001","ldarga.s"),("0x0003","ldfld"),("0x0008","ldarga.s"),("0x000A","ldfld"),("0x000F","call"),("0x0014","ret")]
    need([(r["il"],r["opcode"]) for r in d["instructions"]]==expected,"instruction offsets/opcodes")
    need(d["instructions"][1]["argument_index"]==d["instructions"][3]["argument_index"]==1,"argument reference")
    need([(r["operand"]) for r in d["instructions"] if "operand" in r]==["0x0A000059","0x0A00005A","0x06004FDC"],"IL operands")
    need(len(d["memberref_field_sites"])==d["memberref_field_site_count"]==2,"MemberRef field site count")
    for row in d["memberref_field_sites"]:
        at=int(row["il"],16);tok=int(row["token"],16);rid=tok&0xffffff
        need(body[at]==0x7b and struct.unpack_from("<I",body,at+1)[0]==tok and row["opcode"]=="ldfld","raw field operand")
        mp=o[10]+(rid-1)*z[10];raw=pe[mp:mp+z[10]]
        need(raw.hex()==row["raw_row_hex"],"MemberRef row")
        cwidth=4 if max(rows.get(k,0) for k in (2,1,26,6,27))>=8192 else 2
        parent,mp=base.rd(pe,mp,cwidth);name_id,mp=base.rd(pe,mp,s);sig_id,mp=base.rd(pe,mp,b)
        need(parent==row["memberref_parent_coded"] and base.s_at(pe,sb,name_id)==row["name"] and base.blob(pe,bb,sig_id).hex()==row["signature_blob_hex"],"MemberRef parent/name/signature")
    need(d["branch_count"]==0 and d["direct_methoddef_call_count"]==1,"one child, no branches")
    call=d["direct_methoddef_call_sites"][0]
    at=int(call["il"],16);tok=int(call["token"],16)
    need(body[at]==0x28 and struct.unpack_from("<I",body,at+1)[0]==tok,"raw call token")
    child=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
    need((child[4],child[1],len(child[9]),hashlib.sha256(child[9]).hexdigest(),child[7])==(call["name"],int(call["callee_rva"],16),call["callee_code_size"],call["callee_code_sha256"],(call["owner"],"")),"separate original MethodDef child metadata/body")
    needle=struct.pack("<I",T);patterns=[(b"\x28"+needle,"call"),(b"\x6f"+needle,"callvirt"),(b"\x73"+needle,"newobj"),(b"\x27"+needle,"jmp"),(b"\xfe\x06"+needle,"ldftn"),(b"\xfe\x07"+needle,"ldvirtftn")]
    found=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid; cm=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok);cbody=cm[9]
        if not cbody:continue
        for pat,op in patterns:
            i=0
            while True:
                pos=cbody.find(pat,i)
                if pos<0:break
                found.append(dict(caller_type=cm[7][0],caller_namespace=cm[7][1],caller_method=cm[4],caller_token=f"0x{tok:08X}",caller_rva=f"0x{cm[1]:08X}",caller_code_size=len(cbody),caller_code_sha256=hashlib.sha256(cbody).hexdigest(),call_il=f"0x{pos:04X}",opcode=op))
                i=pos+1
    found.sort(key=lambda x:(int(x["caller_token"],16),int(x["call_il"],16),x["opcode"]))
    need(found==d["direct_in_assembly_references"] and len(found)==d["direct_reference_count"]==d["direct_caller_method_count"]==1,"all direct matching DLL references")
    return {"wrapper_il_bytes":21,"memberref_field_reads":2,"child_methoddef_calls":1,"direct_in_assembly_refs":1}
def verify_r6(path,w):
    c=w["capture_boundary"]
    need(base.sh(path)==c["archive_sha256"],"R6 archive SHA")
    with zipfile.ZipFile(path) as zf:
        need(zf.testzip() is None,"R6 CRC");paths=[n for n in zf.namelist() if Path(n).name=="event_trace.tsv"]
        need(len(paths)==1,"unique R6 trace")
        raw=zf.read(paths[0]);need(hashlib.sha256(raw).hexdigest()==c["event_trace_sha256"],"R6 trace SHA")
        found={k:0 for k in c["checked_method_event_counts"]}
        for row in csv.DictReader(io.StringIO(raw.decode("utf-8-sig")),delimiter="\t"):
            if row["method"] in found:found[row["method"]]+=1
    need(found==c["checked_method_event_counts"] and not any(found.values()) and c["promoted_as_evidence"] is False,"unobserved method recording boundary")
    return found
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--r6",required=True);args=ap.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        need(w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_MOVE_TO_DEST_VECTOR_WRAPPER_V1" and w["source_ids"]==["DLL-001"],"witness identity")
        print(json.dumps({"dll":verify_dll(args.dll,w),"r6":verify_r6(args.r6,w)},indent=2,sort_keys=True))
        print("PROVE_PLAYERCONTROLLER_AI_MOVE_TO_DEST_VECTOR_WRAPPER: PASS");return 0
    except Exception as e:
        print("PROVE_PLAYERCONTROLLER_AI_MOVE_TO_DEST_VECTOR_WRAPPER: FAIL",e);return 1
if __name__=="__main__":raise SystemExit(main())
