#!/usr/bin/env python3
"""Byte-level FACT-0257 verifier against the matching original DLL and R6 recording."""
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_player_status_data_man_get_player_status_data as base
ROOT=Path(__file__).resolve().parents[1]
W=ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_go_back_grapple.summary.json"
T=0x06004FB1
DLL="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
BODY="05aa37f29b638f8da45743303251598eea9a5bf501388a75d7f0208ea0a2175c"
def require(ok,why):
    if not ok:raise RuntimeError(why)
def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack("<I",T);patterns=[(bytes([0x28])+needle,"call"),(bytes([0x6f])+needle,"callvirt"),(bytes([0x73])+needle,"newobj"),(bytes([0x27])+needle,"jmp"),(bytes([0xfe,0x06])+needle,"ldftn"),(bytes([0xfe,0x07])+needle,"ldvirtftn")]
    found=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid;md=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok);body=md[9]
        if not body:continue
        for pat,opc in patterns:
            cursor=0
            while True:
                at=body.find(pat,cursor)
                if at<0:break
                found.append(dict(caller_type=md[7][0],caller_method=md[4],caller_token=f"0x{tok:08X}",caller_rva=f"0x{md[1]:08X}",caller_code_size=len(body),caller_code_sha256=hashlib.sha256(body).hexdigest(),call_il=f"0x{at:04X}",opcode=opc))
                cursor=at+1
    return sorted(found,key=lambda q:(int(q["caller_token"],16),int(q["call_il"],16)))
def dll(path,w):
    pe=Path(path).read_bytes();require(len(pe)==8171008 and hashlib.sha256(pe).hexdigest()==DLL,"source assembly")
    ss,q=base.secs(pe);st,hs,rows,p=base.mdstreams(pe,ss,q);s,b,ix,z,o=base.tables(pe,st,hs,rows,p);sb=st["#Strings"][0];bb=st["#Blob"][0];fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T);m=w["dll"]["method"]
    require((raw,rva,impl,flags,name,sig,owner)==("4c632f000000810068360a00db490000c93a",0x002F634C,0,0x81,"AIActFunc_GoBackGrapple","200002",("PlayerController_AI","")),"MethodDef exact metadata")
    require(pe[base.off(ss,rva):start].hex()==m["fat_header_hex"]=="13300400eb000000f3100011","header")
    loc=o[17]+(0x10F3-1)*z[17];bi,_=base.rd(pe,loc,b)
    require(pe[loc:loc+z[17]].hex()=="fccd0200" and base.blob(pe,bb,bi).hex()=="070212a78811a7dc","local signature")
    require(base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]==plist,"parameters")
    require(len(body)==235 and hashlib.sha256(body).hexdigest()==BODY and body.hex()==m["body_hex"],"complete raw IL")
    require(len(w["dll"]["instructions"])==74 and len(w["dll"]["branches"])==9 and len(w["dll"]["fields"])==20,"instruction/control map")
    for it in w["dll"]["fields"]:
        at=int(it["il"],16);tok=int(it["token"],16)
        require(body[at] in (0x7b,0x7d,0x7e,0x80) and struct.unpack_from("<I",body,at+1)[0]==tok,"field site")
        rw,owner,name,sign=base.field(pe,s,b,z,o,sb,bb,fm,tok)
        require((rw,owner[0],name,sign)==(it["raw_row_hex"],it["owner"],it["name"],it["signature_blob_hex"]),"field row")
    for it in w["dll"]["direct_methoddef_calls"]:
        at=int(it["il"],16);tok=int(it["token"],16)
        require(body[at] in (0x28,0x6f) and struct.unpack_from("<I",body,at+1)[0]==tok,"call site")
        target=base.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        require((it["callee"],it["code_size"],it["code_sha256"])==(target[7][0]+"."+target[4],len(target[9]),hashlib.sha256(target[9]).hexdigest()),"child method")
    for it in w["dll"]["branches"]:
        require(body[int(it["il"],16)] in range(43,69),"branch site")
    require(len(w["dll"]["direct_methoddef_calls"])==6 and w["dll"]["memberref_method_call_count"]==0,"method child count")
    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    require(len(rr)==1 and rr==w["dll"]["direct_in_assembly_references"] and rr[0]["opcode"]=="ldftn","delegate reference")
    return {"bytes":235,"field_sites":20,"child_calls":6,"branches":9,"references":1}
def r6(path,w):
    require(base.sh(path)==R6,"source R6 archive")
    with zipfile.ZipFile(path) as z:
        require(z.testzip() is None,"zip CRC")
        paths=[n for n in z.namelist() if Path(n).name=="event_trace.tsv"];require(len(paths)==1,"event member")
        data=z.read(paths[0]);require(hashlib.sha256(data).hexdigest()==EVENT,"event bytes")
        names={s:0 for s in w["capture_boundary"]["checked_method_names"]}
        for row in csv.DictReader(io.StringIO(data.decode("utf-8-sig")),delimiter=chr(9)):
            if row["method"] in names:names[row["method"]]+=1
        require(len(names)==7 and not any(names.values()) and w["capture_boundary"]["promoted_as_evidence"] is False,"no live event witness")
    return {"checked_names":7,"direct_events":0}
def main():
    p=argparse.ArgumentParser();p.add_argument("--dll",required=True);p.add_argument("--r6",required=True);args=p.parse_args()
    try:
        w=json.loads(W.read_text(encoding="utf-8"));require(w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_AI_ACT_FUNC_GO_BACK_GRAPPLE_V1","dataset name")
        print(json.dumps({"dll":dll(args.dll,w),"r6":r6(args.r6,w)},indent=2));print("PROVE_PLAYERCONTROLLER_AI_GO_BACK_GRAPPLE: PASS");return 0
    except Exception as e:
        print("PROVE_PLAYERCONTROLLER_AI_GO_BACK_GRAPPLE: FAIL",str(e));return 1
if __name__=="__main__":raise SystemExit(main())
