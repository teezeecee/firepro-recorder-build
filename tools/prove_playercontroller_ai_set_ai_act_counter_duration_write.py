#!/usr/bin/env python3
"""FACT-0261: independently replay exact DLL method, callers and R6 boundary."""
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_set_ai_act_counter_duration_write.summary.json"
TOKEN=0x06004FAC

def need(ok,why):
    if not ok: raise RuntimeError(why)

def verify_dll(path,w):
    pe=Path(path).read_bytes()
    d=w["dll"];m=d["method"]
    need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"retail DLL identity")
    ss,q=base.secs(pe); st,hs,rows,p=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
    sb=st["#Strings"][0];bb=st["#Blob"][0]
    fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,TOKEN)
    need((raw,rva,impl,flags,name,sig,owner)==
         (m["methoddef_row_hex"],int(m["rva"],16),int(m["impl_flags_raw"],16),
          int(m["method_attributes_raw"],16),m["name"],m["signature_blob_hex"],(m["owner"],m["namespace"])),"MethodDef metadata")
    need(pe[base.off(ss,rva):start].hex()==m["tiny_header_hex"]=="22","tiny method header")
    need(body.hex()==m["body_hex"]=="02037d4c6100042a" and len(body)==m["code_size"]==8,"exact body")
    need(hashlib.sha256(body).hexdigest()==m["code_sha256"],"body SHA-256")
    nxt=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,TOKEN+1)
    need(nxt[6]==plist+m["parameter_count"]==plist+1,"one Param metadata row")
    pp=o[8]+(plist-1)*z[8]
    need(pe[pp:pp+z[8]].hex()==m["parameter_row_hex"],"parameter row bytes")
    ni,_=base.rd(pe,pp+4,s)
    need(base.s_at(pe,sb,ni)==m["parameter_name"]=="cnt","parameter name")
    expected=[{"il":"0x0000","opcode":"ldarg.0"},
              {"il":"0x0001","opcode":"ldarg.1"},
              {"il":"0x0002","opcode":"stfld","operand":"0x0400614C"},
              {"il":"0x0007","opcode":"ret"}]
    need(d["instructions"]==expected and m["decoded_instruction_count"]==4,"IL instruction boundaries")
    need(d["branch_count"]==d["direct_methoddef_call_count"]==d["memberref_method_call_count"]==0,"no branches or calls")
    need(len(d["fields"])==1,"one field")
    fld=d["fields"][0]
    need((fld["il"],fld["opcode"],fld["token"])==("0x0002","stfld","0x0400614C"),"field location")
    row,own,nm,sig=base.field(pe,s,b,z,o,sb,bb,fm,0x0400614C)
    need((row,own,nm,sig)==(fld["raw_row_hex"],(fld["owner"],""),fld["name"],fld["signature_blob_hex"]),"field metadata")
    needle=struct.pack("<I",TOKEN)
    patterns=[(b"\x28"+needle,"call"),(b"\x6F"+needle,"callvirt"),
              (b"\x73"+needle,"newobj"),(b"\x27"+needle,"jmp"),
              (b"\xFE\x06"+needle,"ldftn"),(b"\xFE\x07"+needle,"ldvirtftn")]
    found=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        c=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        code=c[9]
        if not code: continue
        for pat,opname in patterns:
            at=0
            while True:
                pos=code.find(pat,at)
                if pos<0: break
                found.append(dict(caller_type=c[7][0],caller_namespace=c[7][1],caller_method=c[4],
                    caller_token=f"0x{tok:08X}",caller_rva=f"0x{c[1]:08X}",
                    caller_code_size=len(code),caller_code_sha256=hashlib.sha256(code).hexdigest(),
                    call_il=f"0x{pos:04X}",opcode=opname))
                at=pos+1
    found.sort(key=lambda x:(int(x["caller_token"],16),int(x["call_il"],16),x["opcode"]))
    need(found==d["direct_in_assembly_references"],"complete reference/owner/caller source bytes")
    need(len(found)==d["direct_reference_count"]==4 and len({r["caller_token"] for r in found})==d["direct_caller_method_count"]==3,"reference counts")
    return {"method_code_bytes":8,"field_sites":1,"direct_references":4,"direct_caller_methods":3}

def verify_r6(path,w):
    cap=w["capture_boundary"]
    need(base.sh(path)==cap["archive_sha256"],"R6 zip identity")
    with zipfile.ZipFile(path) as zf:
        need(zf.testzip() is None,"R6 CRC")
        names=[name for name in zf.namelist() if Path(name).name=="event_trace.tsv"]
        need(len(names)==1,"one event trace")
        data=zf.read(names[0])
        need(hashlib.sha256(data).hexdigest()==cap["event_trace_sha256"],"event trace identity")
        seen={k:0 for k in cap["checked_method_event_counts"]}
        for row in csv.DictReader(io.StringIO(data.decode("utf-8-sig")),delimiter="\t"):
            if row["method"] in seen:seen[row["method"]]+=1
    need(seen==cap["checked_method_event_counts"],"exact R6 per-method counts")
    need(seen["PlayerController_AI.SetAIActCounter"]==0 and cap["promoted_as_evidence"] is False,"unobserved target boundary")
    return {"target_method_event_rows":0,"observed_animator_method_rows":seen["FormAnimator.PlayAnimationSE"]}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--dll",required=True)
    ap.add_argument("--r6",required=True)
    a=ap.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        need(w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_COUNTER_V1" and w["source_ids"]==["DLL-001"],"witness identity")
        print(json.dumps({"dll":verify_dll(a.dll,w),"r6":verify_r6(a.r6,w)},indent=2,sort_keys=True))
        print("PROVE_PLAYERCONTROLLER_AI_SET_AI_ACT_COUNTER: PASS")
        return 0
    except Exception as e:
        print("PROVE_PLAYERCONTROLLER_AI_SET_AI_ACT_COUNTER: FAIL",str(e))
        return 1

if __name__=="__main__":
    raise SystemExit(main())
