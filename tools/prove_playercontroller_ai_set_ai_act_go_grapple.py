#!/usr/bin/env python3
"""Verify FACT-0256 from the matching retail DLL and original R6 archive."""
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base

ROOT=Path(__file__).resolve().parents[1]
WITNESS=ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_set_ai_act_go_grapple.summary.json"
METHOD=0x06004F9E
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
BODY_SHA="978e82da32179445718786287df804ca334ac6f1889e726bec8774e5a13ccf12"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
REF_SHA="8b639c74dc7bc8eba15f8ca12a7bceaba095ba45d69aaa2b5ef8eaccc50650be"
CALLER_SHA="6e79f49c660d7087748e3c0b3ccdfee1deecf8edebc7b9f960f73f41d78a136a"
class Mismatch(Exception):pass
def check(v,why):
    if not v:raise Mismatch(why)
def digest(x):
    return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def direct_references(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    operand=struct.pack("<I",METHOD)
    patterns=[(b"\x28"+operand,"call"),(b"\x6f"+operand,"callvirt"),
              (b"\x73"+operand,"newobj"),(b"\x27"+operand,"jmp"),
              (b"\xfe\x06"+operand,"ldftn"),(b"\xfe\x07"+operand,"ldvirtftn")]
    found=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        m=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        body=m[9]
        if not body:continue
        for prefix,opcode in patterns:
            start=0
            while True:
                il=body.find(prefix,start)
                if il<0:break
                found.append(dict(caller_type=m[7][0],caller_namespace=m[7][1],
                    caller_method=m[4],caller_token=f"0x{tok:08X}",
                    caller_rva=f"0x{m[1]:08X}",caller_code_size=len(body),
                    caller_code_sha256=hashlib.sha256(body).hexdigest(),
                    call_il=f"0x{il:04X}",opcode=opcode))
                start=il+1
    return sorted(found,key=lambda x:(int(x["caller_token"],16),int(x["call_il"],16),x["opcode"]))
def verify_dll(path,w):
    pe=Path(path).read_bytes()
    check(len(pe)==8171008 and hashlib.sha256(pe).hexdigest()==DLL_SHA,"raw DLL identity")
    ss,q=base.secs(pe)
    st,hs,rows,p=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,p)
    sb,bb=st["#Strings"][0],st["#Blob"][0]
    fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    raw,rva,impl,flags,name,sig,plist,owner,_,body=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,METHOD)
    md=w["dll"]["method"]
    check((raw,rva,impl,flags,name,sig,owner)==
        ("c65f2f0000008100ce340a00a5cd0200ab3a",0x002F5FC6,0,0x0081,
         "SetAIAct_GoGrapple","20030111870c11a7dc08",("PlayerController_AI","")),"MethodDef metadata")
    check(pe[base.off(ss,rva)]==0x5E and md["tiny_header_hex"]=="5e","tiny header")
    check(len(body)==23 and body.hex()==md["body_hex"] and
          hashlib.sha256(body).hexdigest()==BODY_SHA,"23-byte code body")
    next_method=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,METHOD+1)
    check(next_method[6]==plist+3,"parameter extent")
    for pos,row in enumerate(md["parameter_rows"]):
        rawp=o[8]+(plist+pos-1)*z[8]
        data=pe[rawp:rawp+z[8]]
        flags,ordinal=struct.unpack_from("<HH",data)
        nameref,_=base.rd(pe,rawp+4,s)
        check(data.hex()==row["raw_row_hex"] and ordinal==pos+1 and flags==0 and
              base.s_at(pe,sb,nameref)==row["name"],"parameter row "+str(pos))
    for t in w["dll"]["types"]:
        rid=int(t["token"],16)&0xffffff
        rawtype,typename,namespace,_,_,_=base.typedef(pe,rows,s,ix,z,o,sb,rid)
        check((rawtype,typename,namespace)==(t["raw_typedef_row_hex"],t["name"],t["namespace"]),
              "enum TypeDef "+t["name"])
    check([(x["il"],x["opcode"],x.get("operand")) for x in w["dll"]["instructions"]]==[
        ("0x0000","ldarg.0",None),("0x0001","ldc.i4.1",None),("0x0002","ldarg.3",None),
        ("0x0003","call","0x06004F9D"),("0x0008","ldarg.0",None),
        ("0x0009","ldarg.1",None),("0x000A","stfld","0x04006160"),
        ("0x000F","ldarg.0",None),("0x0010","ldarg.2",None),
        ("0x0011","stfld","0x0400614E"),("0x0016","ret",None)],"instruction witness")
    check(body==bytes.fromhex("021705289d4f000602037d6061000402047d4e6100042a"),"complete emitted IL")
    check(body[3]==0x28 and struct.unpack_from("<I",body,4)[0]==0x06004F9D,
          "single MethodDef call")
    child=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,0x06004F9D)
    check((child[4],len(child[9]),hashlib.sha256(child[9]).hexdigest())==
       ("SetAIAct",102,"58725b1757df7dd4bb511637f82b17f0ec95140b0a213f420cf88b318d04d065"),
       "canonical FACT-0043 child")
    for f in w["dll"]["fields"]:
        tok=int(f["token"],16)
        check(base.field(pe,s,b,z,o,sb,bb,fm,tok)==
           (f["raw_row_hex"],("PlayerController_AI",""),f["name"],f["signature_blob_hex"]),
           "field metadata "+f["name"])
        il=int(f["il"],16)
        check(body[il]==0x7D and struct.unpack_from("<I",body,il+1)[0]==tok,
              "field store "+f["name"])
    check(w["dll"]["branches"]==[] and w["dll"]["memberref_method_call_count"]==0,
          "control/call boundaries")
    refs=direct_references(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    check(len(refs)==6 and refs==w["dll"]["direct_in_assembly_references"] and digest(refs)==REF_SHA,
          "complete six reference map")
    caller_sha=hashlib.sha256(("\n".join(sorted({x["caller_token"] for x in refs}))+"\n").encode()).hexdigest()
    check(caller_sha==CALLER_SHA,"caller token-set digest")
    return dict(bytes=len(body),methoddef_children=1,memberref_calls=0,field_stores=2,branches=0,direct_callers=len(refs))
def verify_r6(path,w):
    check(base.sh(path)==R6_SHA,"raw R6 identity")
    with zipfile.ZipFile(path) as z:
        check(z.testzip() is None,"R6 archive CRC")
        names=[n for n in z.namelist() if Path(n).name=="event_trace.tsv"]
        check(len(names)==1,"R6 event trace member")
        bts=z.read(names[0])
        check(hashlib.sha256(bts).hexdigest()==EVENT_SHA,"R6 event trace identity")
        wanted={n:0 for n in w["capture_boundary"]["checked_method_names"]}
        for row in csv.DictReader(io.StringIO(bts.decode("utf-8-sig")),delimiter="\t"):
            if row["method"] in wanted:wanted[row["method"]]+=1
        check(all(x==0 for x in wanted.values()),"nonzero R6 method/caller event row")
        check(w["capture_boundary"]["promoted_as_evidence"] is False,"R6 oracle boundary")
        return dict(names_checked=len(wanted),event_rows=sum(wanted.values()))
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--dll",required=True)
    p.add_argument("--r6",required=True)
    a=p.parse_args()
    try:
        w=json.loads(WITNESS.read_text(encoding="utf-8"))
        check(w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_GO_GRAPPLE_V1","dataset identity")
        result={"dll":verify_dll(a.dll,w),"r6":verify_r6(a.r6,w)}
        print(json.dumps(result,indent=2,sort_keys=True))
        print("PROVE_PLAYERCONTROLLER_AI_SET_AI_ACT_GO_GRAPPLE: PASS")
        return 0
    except Exception as exc:
        print("PROVE_PLAYERCONTROLLER_AI_SET_AI_ACT_GO_GRAPPLE: FAIL")
        print(str(exc))
        return 1
if __name__=="__main__":raise SystemExit(main())
