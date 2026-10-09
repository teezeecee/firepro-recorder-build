#!/usr/bin/env python3
"""FACT-0259: independently replay original retail method, references and R6 non-events."""
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_go_corner_grapple.summary.json"
TOKEN=0x06004FB2
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
BODY_SHA="3d9416da2398348a2eb7fd294fb81c3c87c1b39f9599a76eda4305b1bd80513d"
def need(ok,why):
    if not ok:raise RuntimeError(why)
def decode(body):
    names={2:"ldarg.0",6:"ldloc.0",10:"stloc.0",22:"ldc.i4.0",31:"ldc.i4.s",32:"ldc.i4",40:"call",42:"ret",59:"beq",111:"callvirt",123:"ldfld",125:"stfld",126:"ldsfld"}
    pc=0;result=[]
    while pc<len(body):
        off=pc;op=body[pc];pc+=1;need(op in names,"unsupported opcode at "+str(off))
        val=None
        if op in (40,111,123,125,126):
            val=f"0x{struct.unpack_from('<I',body,pc)[0]:08X}";pc+=4
        elif op==59:
            delta=struct.unpack_from('<i',body,pc)[0];pc+=4;val=f"0x{pc+delta:04X}"
        elif op==31:
            val=struct.unpack_from('<b',body,pc)[0];pc+=1
        elif op==32:
            val=struct.unpack_from('<i',body,pc)[0];pc+=4
        row=dict(il=f"0x{off:04X}",opcode=names[op])
        if val is not None:row["operand"]=val
        result.append(row)
    need(pc==len(body),"IL decoding boundaries")
    return result
def scan_refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack("<I",TOKEN)
    patterns=[(bytes([0x28])+needle,"call"),(bytes([0x6F])+needle,"callvirt"),(bytes([0x73])+needle,"newobj"),(bytes([0x27])+needle,"jmp"),(bytes([0xFE,0x06])+needle,"ldftn"),(bytes([0xFE,0x07])+needle,"ldvirtftn")]
    out=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        m=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok);code=m[9]
        if not code:continue
        for pattern,op in patterns:
            pos=0
            while True:
                at=code.find(pattern,pos)
                if at<0:break
                out.append(dict(caller_type=m[7][0],caller_namespace=m[7][1],caller_method=m[4],caller_token=f"0x{tok:08X}",caller_rva=f"0x{m[1]:08X}",caller_code_size=len(code),caller_code_sha256=hashlib.sha256(code).hexdigest(),call_il=f"0x{at:04X}",opcode=op))
                pos=at+1
    return sorted(out,key=lambda x:(int(x["caller_token"],16),int(x["call_il"],16),x["opcode"]))
def verify_dll(path,w):
    pe=Path(path).read_bytes();need(len(pe)==8171008 and hashlib.sha256(pe).hexdigest()==DLL_SHA,"DLL identity")
    ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
    sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,TOKEN)
    method=w["dll"]["method"]
    need((raw,rva,impl,flags,name,sig,owner)==("44642f000000810080360a00db490000c93a",0x002F6444,0,0x0081,"AIActFunc_GoCornerGrapple","200002",("PlayerController_AI","")),"MethodDef metadata")
    need(pe[base.off(ss,rva):start].hex()==method["fat_header_hex"]=="13300200360000008e020011","fat header")
    loc=o[17]+(0x028E-1)*z[17];blob_i,_=base.rd(pe,loc,b)
    need(pe[loc:loc+z[17]].hex()=="6b940100" and base.blob(pe,bb,blob_i).hex()=="070112a788","local sig")
    need(base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,TOKEN+1)[6]==plist,"zero parameter rows")
    need(len(body)==54 and hashlib.sha256(body).hexdigest()==BODY_SHA and body.hex()==method["body_hex"],"exact method code")
    ins=decode(body)
    need(ins==w["dll"]["instructions"] and len(ins)==17,"raw decoded instruction map")
    branches=[i for i in ins if i["opcode"]=="beq"]
    need(branches==w["dll"]["branches"] and len(branches)==1,"source branches")
    need(all(i["operand"] in {x["il"] for x in ins} for i in branches),"branch target boundary")
    fieldsites=[i for i in ins if i["opcode"] in ("ldfld","stfld","ldsfld")]
    need(len(fieldsites)==5 and len(w["dll"]["fields"])==5,"field site count")
    for i,expected in zip(fieldsites,w["dll"]["fields"]):
        need((i["il"],i["opcode"],i["operand"])==(expected["il"],expected["opcode"],expected["token"]),"field IL site")
        row,field_owner,name,signature=base.field(pe,s,b,z,o,sb,bb,fm,int(i["operand"],16))
        need((row,field_owner[0],name,signature)==(expected["raw_row_hex"],expected["owner"],expected["name"],expected["signature_blob_hex"]),"field metadata")
    callee_sites=[i for i in ins if i["opcode"] in ("call","callvirt")]
    need(len(callee_sites)==2 and len(w["dll"]["direct_methoddef_calls"])==2 and w["dll"]["memberref_method_call_count"]==0,"child count")
    for i,expected in zip(callee_sites,w["dll"]["direct_methoddef_calls"]):
        need((i["il"],i["opcode"],i["operand"])==(expected["il"],expected["opcode"],expected["token"]),"callee IL site")
        c=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(i["operand"],16))
        need((expected["callee"],expected["code_size"],expected["code_sha256"])==(c[7][0]+"."+c[4],len(c[9]),hashlib.sha256(c[9]).hexdigest()),"callee source bytes")
    found=scan_refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    need(found==w["dll"]["direct_in_assembly_references"] and len(found)==1 and found[0]["opcode"]=="ldftn","matching DLL reference surface")
    return dict(instructions=len(ins),branches=len(branches),field_sites=len(fieldsites),calls=len(callee_sites),direct_references=len(found))
def verify_r6(path,w):
    need(base.sh(path)==R6_SHA,"R6 archive SHA")
    with zipfile.ZipFile(path) as zipf:
        need(zipf.testzip() is None,"R6 CRC")
        names=[n for n in zipf.namelist() if Path(n).name=="event_trace.tsv"]
        need(len(names)==1,"event trace member")
        events=zipf.read(names[0]);need(hashlib.sha256(events).hexdigest()==EVENT_SHA,"event trace SHA")
        target_names=w["capture_boundary"]["checked_method_names"];counts={n:0 for n in target_names}
        for line in csv.DictReader(io.StringIO(events.decode("utf-8-sig")),delimiter=chr(9)):
            if line["method"] in counts:counts[line["method"]]+=1
        need(len(counts)==3 and all(x==0 for x in counts.values()),"direct event rows")
        need(w["capture_boundary"]["promoted_as_evidence"] is False,"no animation claim")
        return dict(checked_names=len(counts),direct_event_rows=sum(counts.values()))
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--dll",required=True);parser.add_argument("--r6",required=True)
    args=parser.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"))
        need(w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_AI_ACT_FUNC_GO_CORNER_GRAPPLE_V1","dataset")
        print(json.dumps({"dll":verify_dll(args.dll,w),"r6":verify_r6(args.r6,w)},indent=2,sort_keys=True))
        print("PROVE_PLAYERCONTROLLER_AI_GO_CORNER_GRAPPLE: PASS");return 0
    except Exception as exc:
        print("PROVE_PLAYERCONTROLLER_AI_GO_CORNER_GRAPPLE: FAIL",str(exc));return 1
if __name__=="__main__":raise SystemExit(main())
