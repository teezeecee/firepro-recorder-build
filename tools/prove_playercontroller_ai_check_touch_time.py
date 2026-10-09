#!/usr/bin/env python3
"""FACT-0262: replay CheckTouch_Time byte/field/branch/ref source without gameplay inference."""
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_check_touch_time.summary.json"
TOKEN=0x06005000
def need(x,msg):
    if not x:raise RuntimeError(msg)
def verify_dll(path,w):
    pe=Path(path).read_bytes();d=w["dll"];m=d["method"]
    need(len(pe)==d["size_bytes"] and hashlib.sha256(pe).hexdigest()==d["sha256"],"original retail DLL identity")
    ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0]
    fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,TOKEN)
    need((raw,rva,impl,flags,name,sig,owner)==(m["methoddef_row_hex"],int(m["rva"],16),int(m["impl_flags_raw"],16),int(m["method_attributes_raw"],16),m["name"],m["signature_blob_hex"],(m["owner"],m["namespace"])),"exact MethodDef metadata")
    need(pe[base.off(ss,rva):start].hex()==m["tiny_header_hex"]=="6a","tiny method header")
    need(body.hex()==m["body_hex"]=="027b4a6100047b3f600004027b706100043f02000000172a162a","26-byte IL body")
    need(len(body)==m["code_size"]==26 and hashlib.sha256(body).hexdigest()==m["code_sha256"],"IL length/hash")
    need(m["parameter_count"]==0 and base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,TOKEN+1)[6]==plist,"zero parameters")
    expected=[("0x0000","ldarg.0",None),("0x0001","ldfld","0x0400614A"),("0x0006","ldfld","0x0400603F"),("0x000B","ldarg.0",None),("0x000C","ldfld","0x04006170"),("0x0011","bgt",None),("0x0016","ldc.i4.1",None),("0x0017","ret",None),("0x0018","ldc.i4.0",None),("0x0019","ret",None)]
    need(len(d["instructions"])==m["decoded_instruction_count"]==10,"instruction count")
    for row,(il,op,operand) in zip(d["instructions"],expected):
        need(row["il"]==il and row["opcode"]==op and (operand is None or row.get("operand")==operand),"instruction metadata "+il)
    need(body[17]==0x3f and struct.unpack_from("<i",body,18)[0]==2 and 17+5+2==24 and body[22:]==bytes.fromhex("172a162a"),"signed branch and two raw Boolean returns")
    need(d["branch_sites"]==[{"il":"0x0011","opcode":"bgt","relative_i32":2,"target_il":"0x0018"}],"branch witness")
    need(d["branch_count"]==1 and d["direct_methoddef_call_count"]==0 and d["memberref_method_call_count"]==0,"branch/call counts")
    need(len(d["fields"])==d["field_site_count"]==3,"field site count")
    for row in d["fields"]:
        at=int(row["il"],16);tok=int(row["token"],16)
        need(body[at]==0x7b and struct.unpack_from("<I",body,at+1)[0]==tok and row["opcode"]=="ldfld","field operand at "+row["il"])
        fraw,own,fn,fsig=base.field(pe,s,b,z,o,sb,bb,fm,tok)
        need((fraw,own,fn,fsig)==(row["raw_row_hex"],(row["owner"],""),row["name"],row["signature_blob_hex"]),"field original metadata "+row["token"])
    needle=struct.pack("<I",TOKEN)
    pats=[(b"\x28"+needle,"call"),(b"\x6f"+needle,"callvirt"),(b"\x73"+needle,"newobj"),(b"\x27"+needle,"jmp"),(b"\xfe\x06"+needle,"ldftn"),(b"\xfe\x07"+needle,"ldvirtftn")]
    found=[]
    for rid in range(1,rows[6]+1):
        ct=0x06000000|rid
        cm=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,ct)
        code=cm[9]
        if not code:continue
        for pat,op in pats:
            p=0
            while True:
                pos=code.find(pat,p)
                if pos<0:break
                found.append({"caller_type":cm[7][0],"caller_namespace":cm[7][1],"caller_method":cm[4],"caller_token":f"0x{ct:08X}","caller_rva":f"0x{cm[1]:08X}","caller_code_size":len(code),"caller_code_sha256":hashlib.sha256(code).hexdigest(),"call_il":f"0x{pos:04X}","opcode":op})
                p=pos+1
    found.sort(key=lambda x:(int(x["caller_token"],16),int(x["call_il"],16),x["opcode"]))
    need(found==d["direct_in_assembly_references"] and len(found)==d["direct_reference_count"]==d["direct_caller_method_count"]==1,"complete matching-DLL MethodDef reference scan")
    return {"exact_method_bytes":26,"field_reads":3,"branches":1,"in_assembly_references":1}
def verify_r6(path,w):
    c=w["capture_boundary"]
    need(base.sh(path)==c["archive_sha256"],"R6 archive hash")
    with zipfile.ZipFile(path) as z:
        need(z.testzip() is None,"R6 CRC")
        names=[n for n in z.namelist() if Path(n).name=="event_trace.tsv"]
        need(len(names)==1,"one R6 trace")
        raw=z.read(names[0])
        need(hashlib.sha256(raw).hexdigest()==c["event_trace_sha256"],"R6 event trace SHA")
        counts={k:0 for k in c["checked_method_event_counts"]}
        for row in csv.DictReader(io.StringIO(raw.decode("utf-8-sig")),delimiter="\t"):
            if row["method"] in counts:counts[row["method"]]+=1
        need(counts==c["checked_method_event_counts"],"direct event counts")
        need(all(v==0 for v in counts.values()) and c["promoted_as_evidence"] is False,"no event promotion")
    return counts
def main():
    a=argparse.ArgumentParser();a.add_argument("--dll",required=True);a.add_argument("--r6",required=True);p=a.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        need(w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_CHECK_TOUCH_TIME_V1" and w["source_ids"]==["DLL-001"],"witness ID")
        print(json.dumps({"dll":verify_dll(p.dll,w),"r6":verify_r6(p.r6,w)},indent=2,sort_keys=True))
        print("PROVE_PLAYERCONTROLLER_AI_CHECK_TOUCH_TIME: PASS");return 0
    except Exception as e:
        print("PROVE_PLAYERCONTROLLER_AI_CHECK_TOUCH_TIME: FAIL",e);return 1
if __name__=="__main__":raise SystemExit(main())
