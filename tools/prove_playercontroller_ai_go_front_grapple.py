#!/usr/bin/env python3
"""Raw source/verifier for FACT-0258: matching retail DLL and original R6 archive."""
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_go_front_grapple.summary.json"
TOKEN=0x06004FB0
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
BODY_SHA="fe0478463f631f1ff67e0445960fb13a4d4e7b436d2a261f50716bb116f6ba3f"
def need(x,why):
    if not x:raise RuntimeError(why)
def instructions(body):
    ops={2:"ldarg.0",3:"ldarg.1",4:"ldarg.2",5:"ldarg.3",6:"ldloc.0",7:"ldloc.1",8:"ldloc.2",9:"ldloc.3",10:"stloc.0",11:"stloc.1",12:"stloc.2",13:"stloc.3",21:"ldc.i4.m1",22:"ldc.i4.0",23:"ldc.i4.1",24:"ldc.i4.2",31:"ldc.i4.s",32:"ldc.i4",34:"ldc.r4",37:"dup",40:"call",42:"ret",56:"br",57:"brfalse",58:"brtrue",59:"beq",60:"bge",61:"bgt",62:"ble",63:"blt",64:"bne.un",65:"bge.un",66:"bgt.un",67:"ble.un",68:"blt.un",88:"add",96:"or",111:"callvirt",123:"ldfld",125:"stfld",126:"ldsfld",128:"stsfld"}
    pc=0;result=[]
    while pc<len(body):
        pos=pc;raw=body[pc];pc+=1;need(raw in ops,f"opcode {pos:#x}")
        name=ops[raw];val=None
        if raw in (40,111,123,125,126,128):
            val=f"0x{struct.unpack_from('<I',body,pc)[0]:08X}";pc+=4
        elif 56<=raw<=68:
            delta=struct.unpack_from('<i',body,pc)[0];pc+=4;val=f"0x{pc+delta:04X}"
        elif raw==31:
            val=struct.unpack_from('<b',body,pc)[0];pc+=1
        elif raw==32:
            val=struct.unpack_from('<i',body,pc)[0];pc+=4
        elif raw==34:
            val=f"0x{struct.unpack_from('<I',body,pc)[0]:08X}";pc+=4
        row=dict(il=f"0x{pos:04X}",opcode=name)
        if val is not None:row["operand"]=val
        result.append(row)
    need(pc==len(body),"IL boundaries")
    return result
def refscan(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack("<I",TOKEN)
    patterns=[(bytes([0x28])+needle,"call"),(bytes([0x6F])+needle,"callvirt"),(bytes([0x73])+needle,"newobj"),(bytes([0x27])+needle,"jmp"),(bytes([0xFE,0x06])+needle,"ldftn"),(bytes([0xFE,0x07])+needle,"ldvirtftn")]
    out=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid;m=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok);body=m[9]
        if not body:continue
        for pat,op in patterns:
            scan=0
            while True:
                il=body.find(pat,scan)
                if il<0:break
                out.append(dict(caller_type=m[7][0],caller_namespace=m[7][1],caller_method=m[4],caller_token=f"0x{tok:08X}",caller_rva=f"0x{m[1]:08X}",caller_code_size=len(body),caller_code_sha256=hashlib.sha256(body).hexdigest(),call_il=f"0x{il:04X}",opcode=op))
                scan=il+1
    return sorted(out,key=lambda x:(int(x["caller_token"],16),int(x["call_il"],16),x["opcode"]))
def verify_dll(path,w):
    pe=Path(path).read_bytes();need(len(pe)==8171008 and hashlib.sha256(pe).hexdigest()==DLL_SHA,"matching DLL")
    ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
    sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,TOKEN)
    m=w["dll"]["method"]
    need((raw,rva,impl,flags,name,sig,owner)==("34622f00000081004f360a00db490000c93a",0x002F6234,0,0x0081,"AIActFunc_GoFrontGrapple","200002",("PlayerController_AI","")),"MethodDef metadata")
    need(pe[base.off(ss,rva):start].hex()==m["fat_header_hex"]=="133004000a010000f2100011","fat header")
    loc=o[17]+(0x10F2-1)*z[17];bi,_=base.rd(pe,loc,b)
    need(pe[loc:loc+z[17]].hex()=="f3cd0200" and base.blob(pe,bb,bi).hex()=="070211a7dc12a788","local signature")
    need(base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,TOKEN+1)[6]==plist,"no parameter rows")
    need(len(body)==266 and hashlib.sha256(body).hexdigest()==BODY_SHA and body.hex()==m["body_hex"],"full raw body")
    ins=instructions(body)
    need(ins==w["dll"]["instructions"] and len(ins)==80,"all IL instruction bytes and boundaries")
    branches=[x for x in ins if x["opcode"] in ("br","brtrue","brfalse","beq","bne.un","blt.un","ble.un")]
    need(branches==w["dll"]["branches"] and len(branches)==11,"exact branch map")
    need(all(x["operand"] in {p["il"] for p in ins} for x in branches),"branch target instruction boundary")
    fields=[x for x in ins if x["opcode"] in ("ldfld","stfld","ldsfld","stsfld")]
    need(len(fields)==22 and len(w["dll"]["fields"])==22,"field reference count")
    for x,expected in zip(fields,w["dll"]["fields"]):
        need((x["il"],x["opcode"],x["operand"])==(expected["il"],expected["opcode"],expected["token"]),"field IL site")
        row,own,nm,sg=base.field(pe,s,b,z,o,sb,bb,fm,int(x["operand"],16))
        need((row,own[0],nm,sg)==(expected["raw_row_hex"],expected["owner"],expected["name"],expected["signature_blob_hex"]),"field metadata")
    calls=[x for x in ins if x["opcode"] in ("call","callvirt")]
    need(len(calls)==7 and len(w["dll"]["direct_methoddef_calls"])==7,"callee count")
    for x,expected in zip(calls,w["dll"]["direct_methoddef_calls"]):
        need((x["il"],x["opcode"],x["operand"])==(expected["il"],expected["opcode"],expected["token"]),"callee IL site")
        child=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,int(x["operand"],16))
        need((expected["callee"],expected["code_size"],expected["code_sha256"])==(child[7][0]+"."+child[4],len(child[9]),hashlib.sha256(child[9]).hexdigest()),"matching DLL callee")
    need(w["dll"]["memberref_method_call_count"]==0,"no MemberRef methods")
    found=refscan(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    need(found==w["dll"]["direct_in_assembly_references"] and len(found)==1 and found[0]["opcode"]=="ldftn","all MethodDef references")
    return {"instructions":len(ins),"branches":len(branches),"fields":len(fields),"callees":len(calls),"direct_references":len(found)}
def verify_r6(path,w):
    need(base.sh(path)==R6_SHA,"R6 archive identity")
    with zipfile.ZipFile(path) as z:
        need(z.testzip() is None,"R6 CRC")
        events=[n for n in z.namelist() if Path(n).name=="event_trace.tsv"]
        need(len(events)==1,"event trace member")
        bt=z.read(events[0]);need(hashlib.sha256(bt).hexdigest()==EVENT_SHA,"event source bytes")
        counts={name:0 for name in w["capture_boundary"]["checked_method_names"]}
        for row in csv.DictReader(io.StringIO(bt.decode("utf-8-sig")),delimiter=chr(9)):
            if row["method"] in counts:counts[row["method"]]+=1
        need(len(counts)==8 and all(v==0 for v in counts.values()),"R6 no-event boundary")
        need(w["capture_boundary"]["promoted_as_evidence"] is False,"capture not promoted")
        return {"checked_method_names":len(counts),"direct_event_rows":sum(counts.values())}
def main():
    p=argparse.ArgumentParser();p.add_argument("--dll",required=True);p.add_argument("--r6",required=True);a=p.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"));need(w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_AI_ACT_FUNC_GO_FRONT_GRAPPLE_V1","dataset identity")
        print(json.dumps({"dll":verify_dll(a.dll,w),"r6":verify_r6(a.r6,w)},indent=2,sort_keys=True))
        print("PROVE_PLAYERCONTROLLER_AI_GO_FRONT_GRAPPLE: PASS");return 0
    except Exception as exc:
        print("PROVE_PLAYERCONTROLLER_AI_GO_FRONT_GRAPPLE: FAIL",str(exc));return 1
if __name__=="__main__":raise SystemExit(main())
