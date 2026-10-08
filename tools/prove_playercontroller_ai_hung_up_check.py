#!/usr/bin/env python3
"""Independent raw-DLL/R6 verification of canonical FACT-0255. No execution semantics guessed."""
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

ROOT=Path(__file__).resolve().parents[1]
WITNESS=ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_hung_up_check.summary.json"
T=0x06004FD9
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
BODY_SHA="bd6e95d91e9c741be24e1cd719aa40f61488fd454e77e8003688abb237bb2106"
FIELD_SHA="1ba344c5862683c55db1f19c246a4f33d52a32d94d8f06ca96a376cf6f8add74"
CALL_SHA="b40b9b622d11c51cfe98ac9eef5d4126f099de7cb362062ba5f2a031c3268f4c"
BRANCH_SHA="00e7461af0b32f93d5e25432bb4f3ca1349cb1456a4bdbc833daf49bb607f1d8"
REF_SHA="e2896d3eae44da9e8dafa281f3d7062add43367154c0a2cbd9d86cd6eeb2b2a4"
CALLER_SHA="f99adb0c84c2ab38c178c86d7be78b924e6f9f05a1ff43de92854a5b4e01f6e0"
OP={
 0x02:("ldarg.0",0),0x06:("ldloc.0",0),0x07:("ldloc.1",0),0x08:("ldloc.2",0),
 0x0a:("stloc.0",0),0x0b:("stloc.1",0),0x0c:("stloc.2",0),0x0d:("stloc.3",0),
 0x12:("ldloca.s",1),0x16:("ldc.i4.0",0),0x17:("ldc.i4.1",0),
 0x1e:("ldc.i4.8",0),0x22:("ldc.r4",4),0x25:("dup",0),0x28:("call",4),
 0x2a:("ret",0),0x38:("br",4),0x39:("brfalse",4),0x3c:("bge",4),
 0x3f:("blt",4),0x41:("bgt.un",4),0x44:("blt.un",4),
 0x58:("add",0),0x5d:("rem",0),0x71:("ldobj",4),0x7b:("ldfld",4),
 0x7d:("stfld",4),0x81:("stobj",4),0x8f:("ldelema",4)}
BRANCHES={"br","brfalse","bge","blt","bgt.un","blt.un"}
class EvidenceMismatch(RuntimeError):pass
def demand(ok,label):
    if not ok:raise EvidenceMismatch(label)
def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def decode(body):
    result=[];pos=0
    while pos<len(body):
        code=body[pos]
        demand(code in OP,f"unsupported IL opcode at {pos:#x}: {code:#x}")
        name,n=OP[code]; demand(pos+1+n<=len(body),"truncated IL")
        val=None
        if n==1:val=body[pos+1]
        if n==4:
            if name in BRANCHES:val=f"0x{pos+5+struct.unpack_from('<i',body,pos+1)[0]:04X}"
            elif name=="ldc.r4":val=struct.unpack_from('<f',body,pos+1)[0]
            else:val=f"0x{struct.unpack_from('<I',body,pos+1)[0]:08X}"
        result.append({"il":f"0x{pos:04X}","opcode":name,**({"operand":val} if val is not None else {})})
        pos+=n+1
    demand(pos==len(body),"IL extent")
    return result
def reference_surface(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack("<I",T)
    pats=[(b"\x28"+needle,"call"),(b"\x6f"+needle,"callvirt"),
          (b"\x73"+needle,"newobj"),(b"\x27"+needle,"jmp"),
          (b"\xfe\x06"+needle,"ldftn"),(b"\xfe\x07"+needle,"ldvirtftn")]
    found=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        body=md[9]
        if not body:continue
        for needle_op,opname in pats:
            i=0
            while True:
                at=body.find(needle_op,i)
                if at<0:break
                found.append({"caller_type":md[7][0] if md[7] else None,
                  "caller_namespace":md[7][1] if md[7] else None,
                  "caller_method":md[4],"caller_token":f"0x{tok:08X}",
                  "caller_rva":f"0x{md[1]:08X}","caller_code_size":len(body),
                  "caller_code_sha256":hashlib.sha256(body).hexdigest(),
                  "call_il":f"0x{at:04X}","opcode":opname})
                i=at+1
    return sorted(found,key=lambda x:(int(x["caller_token"],16),int(x["call_il"],16),x["opcode"]))
def verify_dll(dll,w):
    pe=Path(dll).read_bytes()
    demand(len(pe)==8171008 and hashlib.sha256(pe).hexdigest()==DLL_SHA,"raw DLL identity")
    ss,q=base.secs(pe)
    st,hs,rows,tp=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
    sb=st["#Strings"][0];bb=st["#Blob"][0]
    fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    raw,rva,impl,flags,name,sig,plist,owner,_,body=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    m=w["dll"]["method"]
    demand((raw,rva,impl,flags,name,sig,owner)==("e4912f0000008100f7390a00db490000ce3a",0x002F91E4,0,0x0081,"HungUpCheck","200002",("PlayerController_AI","")),"MethodDef")
    demand(base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]==plist,"parameters")
    p=base.off(ss,rva)
    demand(pe[p:p+12].hex()=="13300300fa00000009110011","fat header")
    demand(len(body)==250 and hashlib.sha256(body).hexdigest()==BODY_SHA and body.hex()==m["body_hex"],"raw body")
    loc=0x11001109&0xffffff;p=o[17]+(loc-1)*z[17]
    sigidx,_=base.rd(pe,p,b)
    demand(pe[p:p+z[17]].hex()=="37cf0200" and base.blob(pe,bb,sigidx).hex()=="070412a82c1131081131","local signature")
    ins=decode(body)
    demand(len(ins)==89==m["decoded_instruction_count"],"IL decode")
    field_access=[{"il":v["il"],"opcode":v["opcode"],"token":v["operand"]}
      for v in ins if v["opcode"] in ("ldfld","stfld") and str(v.get("operand","")).startswith("0x04")]
    demand(len(field_access)==19 and field_access==w["dll"]["field_accesses"] and digest(field_access)==FIELD_SHA,"field access map")
    for field in w["dll"]["fields"]:
        got=base.field(pe,s,b,z,o,sb,bb,fm,int(field["token"],16))
        expected=(field["raw_row_hex"],(field["owner"],""),field["name"],field["signature_blob_hex"])
        demand(got==expected,"field metadata "+field["token"])
    calls=[{"il":v["il"],"opcode":v["opcode"],"token":v["operand"]} for v in ins if v["opcode"]=="call"]
    demand(len(calls)==9 and calls==w["dll"]["calls"] and digest(calls)==CALL_SHA,"method call map")
    branches=[{"il":v["il"],"opcode":v["opcode"],"target":v["operand"]} for v in ins if v["opcode"] in BRANCHES]
    demand(len(branches)==6 and branches==w["dll"]["branches"] and digest(branches)==BRANCH_SHA,"branch graph")
    expected_children=[(0x0B,0x06005074,"GetPlayerStatusData",25,"3654b9b747fafe496cea44043ad40832a25d81f2537b71d46331b87e7bac4cb3"),(0x2D,0x06004FD8,"Reset_HungUpCheck",55,"9bea2fa5e79dc6e2c45acd5a83161a0ce0bec614c28ca0c2f0e63037bb0b2e01")]
    for il,tok,nm,size,sha in expected_children:
        demand(body[il]==0x28 and struct.unpack_from("<I",body,il+1)[0]==tok,"MethodDef call "+nm)
        child=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        demand(child[4]==nm and len(child[9])==size and hashlib.sha256(child[9]).hexdigest()==sha,"canonical child "+nm)
    all_external=[v for v in calls if v["token"].startswith("0x0A")]
    demand(len(all_external)==7,"external MemberRef call count")
    for member in w["dll"]["memberref_calls"]:
        tok=int(member["token"],16);rid=tok&0xffffff
        p=o[10]+(rid-1)*z[10]
        parent_size=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=8192 else 2
        ni,q=base.rd(pe,p+parent_size,s)
        si,_=base.rd(pe,q,b)
        demand((pe[p:p+z[10]].hex(),base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex())==
           (member["raw_row_hex"],member["name"],member["signature_blob_hex"]),"MemberRef metadata "+member["token"])
        actual=[v["il"] for v in all_external if v["token"]==member["token"]]
        demand(actual==member["call_ils"],"MemberRef call sites "+member["token"])
    demand([(v["il"],v["opcode"],v.get("operand")) for v in ins if v["opcode"] in ("ldc.i4.8","rem","ldc.r4")]==[
     ("0x007D","ldc.i4.8",None),("0x007E","rem",None),("0x008A","ldc.i4.8",None),
     ("0x00BC","ldc.i4.8",None),("0x00C3","ldc.r4",8.0),
     ("0x00EC","ldc.r4",struct.unpack("<f",bytes.fromhex("0ad7a33c"))[0])],"raw comparison constants")
    refs=reference_surface(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    demand(len(refs)==5 and refs==w["dll"]["direct_in_assembly_references"] and digest(refs)==REF_SHA,"complete caller surface")
    caller_digest=hashlib.sha256(("\n".join(sorted({v["caller_token"] for v in refs}))+"\n").encode()).hexdigest()
    demand(caller_digest==CALLER_SHA,"caller token set")
    return {"code_bytes":len(body),"instructions":len(ins),"MethodDef_children":2,"MemberRef_calls":len(all_external),"caller_count":len(refs)}
def verify_r6(path,w):
    demand(base.sh(path)==R6_SHA,"R6 raw archive hash")
    with zipfile.ZipFile(path) as z:
        demand(z.testzip() is None,"R6 CRC")
        names=[name for name in z.namelist() if Path(name).name=="event_trace.tsv"]
        demand(len(names)==1,"R6 event member")
        payload=z.read(names[0])
        demand(hashlib.sha256(payload).hexdigest()==EVENT_SHA,"R6 event trace hash")
        wanted={"PlayerController_AI.HungUpCheck","PlayerController_AI.AIActFunc_GoFrontGrapple",
          "PlayerController_AI.AIActFunc_GoBackGrapple","PlayerController_AI.AIActFunc_DownAttack",
          "PlayerController_AI.AIActFunc_GoAround","PlayerController_AI.AIActFunc_StandAtk",
          "PlayerController_AI.Reset_HungUpCheck","PlayerStatusDataMan.GetPlayerStatusData"}
        counter={name:0 for name in wanted}
        for row in csv.DictReader(io.StringIO(payload.decode("utf-8-sig")),delimiter="\t"):
            if row["method"] in counter:counter[row["method"]]+=1
        demand(all(v==0 for v in counter.values()) and w["capture_boundary"]["promoted_as_evidence"] is False,"R6 negative boundary")
        return {"checked_methods":len(counter),"nonzero_rows":sum(counter.values())}
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--dll",required=True)
    ap.add_argument("--r6",required=True)
    args=ap.parse_args()
    try:
        w=json.loads(WITNESS.read_text(encoding="utf-8"))
        demand(w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_HUNG_UP_CHECK_V1","dataset id")
        result={"dll":verify_dll(args.dll,w),"r6":verify_r6(args.r6,w)}
        print(json.dumps(result,indent=2,sort_keys=True))
        print("PROVE_PLAYERCONTROLLER_AI_HUNG_UP_CHECK: PASS")
        return 0
    except Exception as exc:
        print("PROVE_PLAYERCONTROLLER_AI_HUNG_UP_CHECK: FAIL")
        print(str(exc))
        return 1
if __name__=="__main__":raise SystemExit(main())
