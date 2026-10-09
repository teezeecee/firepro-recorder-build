#!/usr/bin/env python3
"""FACT-0260: replay raw retail DLL body/references and original R6 non-events."""
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_do_nothing.summary.json"
TOKEN=0x06004FAE

def need(ok,why):
    if not ok:
        raise RuntimeError(why)

def verify_dll(path,w):
    pe=Path(path).read_bytes()
    need(len(pe)==w["dll"]["size_bytes"] and hashlib.sha256(pe).hexdigest()==w["dll"]["sha256"],"DLL identity")
    ss,q=base.secs(pe)
    st,hs,rows,p=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
    sb=st["#Strings"][0]
    bb=st["#Blob"][0]
    _,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,TOKEN)
    m=w["dll"]["method"]
    need((raw,rva,impl,flags,name,sig,owner)==
         (m["methoddef_row_hex"],int(m["rva"],16),int(m["impl_flags_raw"],16),
          int(m["method_attributes_raw"],16),m["name"],m["signature_blob_hex"],(m["owner"],m["namespace"])),"MethodDef metadata")
    offset=base.off(ss,rva)
    need(pe[offset:start].hex()==m["tiny_header_hex"],"tiny method header")
    need(len(body)==m["code_size"]==2 and body.hex()==m["body_hex"]=="162a","exact code")
    need(hashlib.sha256(body).hexdigest()==m["code_sha256"],"code SHA")
    need(base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,TOKEN+1)[6]==plist,"parameter count")
    need(w["dll"]["instructions"]==[{"il":"0x0000","opcode":"ldc.i4.0"},{"il":"0x0001","opcode":"ret"}],"exact two instructions")
    need(all(w["dll"][k]==0 for k in ("field_access_count","direct_methoddef_call_count","memberref_method_call_count","branch_count")),"no control-flow additions")

    needle=struct.pack("<I",TOKEN)
    patterns=[(bytes([0x28])+needle,"call"),(bytes([0x6f])+needle,"callvirt"),
              (bytes([0x73])+needle,"newobj"),(bytes([0x27])+needle,"jmp"),
              (bytes([0xfe,0x06])+needle,"ldftn"),(bytes([0xfe,0x07])+needle,"ldvirtftn")]
    refs=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        c=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        code=c[9]
        if not code:
            continue
        for pattern,opcode in patterns:
            at=0
            while True:
                pos=code.find(pattern,at)
                if pos<0:
                    break
                refs.append(dict(caller_type=c[7][0],caller_namespace=c[7][1],caller_method=c[4],
                    caller_token=f"0x{tok:08X}",caller_rva=f"0x{c[1]:08X}",
                    caller_code_size=len(code),caller_code_sha256=hashlib.sha256(code).hexdigest(),
                    call_il=f"0x{pos:04X}",opcode=opcode))
                at=pos+1
    refs.sort(key=lambda r:(int(r["caller_token"],16),int(r["call_il"],16),r["opcode"]))
    need(refs==w["dll"]["direct_in_assembly_references"],"full matching DLL reference map")
    need(len(refs)==w["dll"]["direct_reference_count"]==w["dll"]["direct_caller_method_count"]==1,"unique pointer reference")
    need(refs[0]["opcode"]=="ldftn" and refs[0]["call_il"]=="0x0023","Init delegate pointer")
    return {"instructions":2,"fields":0,"method_calls":0,"direct_references":len(refs)}

def verify_r6(path,w):
    cb=w["capture_boundary"]
    need(base.sh(path)==cb["archive_sha256"],"R6 ZIP identity")
    with zipfile.ZipFile(path) as f:
        need(f.testzip() is None,"R6 CRC")
        names=[x for x in f.namelist() if Path(x).name=="event_trace.tsv"]
        need(len(names)==1,"exactly one event trace")
        events=f.read(names[0])
        need(hashlib.sha256(events).hexdigest()==cb["event_trace_sha256"],"R6 event trace identity")
        count={x:0 for x in cb["checked_method_names"]}
        for row in csv.DictReader(io.StringIO(events.decode("utf-8-sig")),delimiter="\t"):
            if row["method"] in count:
                count[row["method"]]+=1
    need(len(count)==2 and sum(count.values())==cb["checked_names_event_row_count"]==0,"R6 method-event boundary")
    need(cb["promoted_as_evidence"] is False,"not an observed behavior")
    return {"checked_methods":len(count),"direct_events":0}

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--dll",required=True)
    a.add_argument("--r6",required=True)
    args=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        need(w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_AI_ACT_FUNC_DO_NOTHING_V1","dataset")
        print(json.dumps({"dll":verify_dll(args.dll,w),"r6":verify_r6(args.r6,w)},indent=2,sort_keys=True))
        print("PROVE_PLAYERCONTROLLER_AI_DO_NOTHING: PASS")
        return 0
    except Exception as exc:
        print("PROVE_PLAYERCONTROLLER_AI_DO_NOTHING: FAIL",str(exc))
        return 1

if __name__=="__main__":
    raise SystemExit(main())
