#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from collections import Counter
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
INIT_RVA,INIT_SIZE=0x002DA2D8,1231
INIT_CODE_SHA="88f9c7d05b183bd3ca737eaa8a23aa9e7a01547134f0caedbd3f8caa13ace396"
UPDATE_RVA,UPDATE_SIZE=0x002DB890,738
UPDATE_CODE_SHA="1e18c732ea0674fae8fdecc0b0d06fc976ec4494df663156925e99c4485b4c00"
WITNESS_SHA="b93ad305982a99a0771b7f833951d22ded564dd5539aeaaeae764637c7dae440"
REQ={"FormAnimator.ReqBasicAnm","FormAnimator.ReqSlotAnm","FormAnimator.ReqSerialAnm","FormAnimator.ReqSkillAnm"}

class ProofError(RuntimeError): pass

def sha_path(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda:f.read(1024*1024),b""): h.update(c)
    return h.hexdigest()

def sha_stream(f):
    h=hashlib.sha256()
    for c in iter(lambda:f.read(1024*1024),b""): h.update(c)
    return h.hexdigest()

def sections(pe):
    q=struct.unpack_from("<I",pe,0x3C)[0]
    if pe[q:q+4]!=b"PE\0\0": raise ProofError("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0]; osz=struct.unpack_from("<H",pe,q+20)[0]
    s=q+24+osz; out=[]
    for i in range(n):
        o=s+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        out.append((va,vs,rp,rs))
    return out

def rvaoff(pe,ss,rva):
    for va,vs,rp,rs in ss:
        if va<=rva<va+max(vs,rs): return rp+rva-va
    raise ProofError("RVA unmapped")

def mcode(pe,ss,rva):
    o=rvaoff(pe,ss,rva); b=pe[o]
    if b&3==2: h=1; n=b>>2
    elif b&3==3:
        fs=struct.unpack_from("<H",pe,o)[0]; h=(fs>>12)*4; n=struct.unpack_from("<I",pe,o+4)[0]
    else: raise ProofError("bad IL header")
    return pe[o+h:o+h+n]

def tok(code,off,op,t,label):
    if code[off]!=op or struct.unpack_from("<I",code,off+1)[0]!=t:
        raise ProofError(label)

def verify_dll(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes(); ss=sections(pe)
    init=mcode(pe,ss,INIT_RVA); update=mcode(pe,ss,UPDATE_RVA)
    if len(init)!=INIT_SIZE or hashlib.sha256(init).hexdigest()!=INIT_CODE_SHA: raise ProofError("Init body")
    if len(update)!=UPDATE_SIZE or hashlib.sha256(update).hexdigest()!=UPDATE_CODE_SHA: raise ProofError("Update body")
    tok(update,0x002E,0x7B,0x04005EEC,"reqAnmInit read")
    if update[0x0033]!=0x39: raise ProofError("reqAnmInit branch")
    tok(update,0x0039,0x28,0x06004E73,"Init call")
    if update[0x003F]!=0x16: raise ProofError("clear constant")
    tok(update,0x0040,0x7D,0x04005EEC,"reqAnmInit clear")
    tok(init,0x000B,0x7E,0x040061FA,"PlayerMan.inst")
    tok(init,0x0011,0x7B,0x04005ECE,"plObj")
    tok(init,0x0016,0x7B,0x04005FB1,"TargetPlIdx")
    tok(init,0x001B,0x6F,0x06005065,"GetPlObj")
    for o in (0x01EB,0x023D,0x0453): tok(init,o,0x28,0x06004E75,"StartAnm")
    for o in (0x0215,0x02A8,0x031D,0x03BB,0x0483): tok(init,o,0x28,0x06004E76,"StartOpponentAnm")
    for o in (0x0335,0x03D3,0x03EB): tok(init,o,0x28,0x06004E77,"StartOpponentAnmM")
    return {"dll_sha256":got,"init_code_sha256":INIT_CODE_SHA,"update_code_sha256":UPDATE_CODE_SHA}

def verify_r6(path):
    got=sha_path(path)
    if got!=R6_SHA: raise ProofError("R6 SHA "+got)
    with zipfile.ZipFile(path) as z:
        bad=z.testzip()
        if bad: raise ProofError("ZIP CRC "+bad)
        names=[n for n in z.namelist() if Path(n).name=="event_trace.tsv"]
        if len(names)!=1: raise ProofError("event_trace count")
        name=names[0]
        with z.open(name) as f: esha=sha_stream(f)
        if esha!=EVENT_SHA: raise ProofError("event SHA "+esha)
        stack=[]; records=[]; pre=post=0; trip=Counter(); soreq=Counter(); smreq=Counter()
        with z.open(name) as raw:
            rd=csv.DictReader(io.TextIOWrapper(raw,encoding="utf-8-sig",newline=""),delimiter="\t")
            for line,row in enumerate(rd,start=2):
                if row["phase"]=="PRE":
                    node={"line":line,"row":dict(row),"children":[]}
                    if stack: stack[-1]["children"].append(node)
                    stack.append(node)
                    if row["method"]=="FormAnimator.InitAnimation": pre+=1
                elif row["phase"]=="POST":
                    if not stack: raise ProofError("POST without PRE")
                    node=stack.pop()
                    if node["row"]["method"]!=row["method"] or node["row"]["instance"]!=row["instance"]:
                        raise ProofError("non-LIFO trace")
                    if row["method"]!="FormAnimator.InitAnimation": continue
                    post+=1; p=node["row"]
                    st=[x for x in node["children"] if x["row"]["method"]=="FormAnimator.StartAnm"]
                    so=[x for x in node["children"] if x["row"]["method"]=="FormAnimator.StartOpponentAnm"]
                    sm=[x for x in node["children"] if x["row"]["method"]=="FormAnimator.StartOpponentAnmM"]
                    if len(st)!=1 or len(so)>1 or len(sm)>1: raise ProofError("child multiplicity")
                    s=st[0]
                    if s["row"]["args"]!="0" or s["row"]["instance"]!=p["instance"] or s["row"]["owner_slot"]!=p["owner_slot"]:
                        raise ProofError("StartAnm relation")
                    soline=soreqline=smline=smreqline=0
                    if so:
                        a=[x.strip() for x in so[0]["row"]["args"].split("|")]
                        rr=[x for x in so[0]["children"] if x["row"]["method"] in REQ]
                        if len(a)!=2 or a[0]!=p["target"] or a[1]!="1": raise ProofError("StartOpponent args")
                        if so[0]["row"]["instance"]!=p["instance"] or so[0]["row"]["owner_slot"]!=p["owner_slot"]: raise ProofError("StartOpponent host")
                        if len(rr)!=1 or rr[0]["row"]["owner_slot"]!=p["target"]: raise ProofError("StartOpponent owner")
                        soreq[rr[0]["row"]["method"]]+=1; soline=so[0]["line"]; soreqline=rr[0]["line"]
                    if sm:
                        a=[x.strip() for x in sm[0]["row"]["args"].split("|")]
                        rr=[x for x in sm[0]["children"] if x["row"]["method"] in REQ]
                        if len(a)!=3 or a[1]!="2" or a[2]!=p["target"]: raise ProofError("StartOpponentM args")
                        if sm[0]["row"]["instance"]!=p["instance"] or sm[0]["row"]["owner_slot"]!=p["owner_slot"]: raise ProofError("StartOpponentM host")
                        if len(rr)!=1 or rr[0]["row"]["owner_slot"]!=a[0]: raise ProofError("StartOpponentM owner")
                        smreq[rr[0]["row"]["method"]]+=1; smline=sm[0]["line"]; smreqline=rr[0]["line"]
                    trip[(1,len(so),len(sm))]+=1
                    records.append((node["line"],line,s["line"],soline,soreqline,smline,smreqline))
        if stack: raise ProofError("unterminated PRE")
    if pre!=5288 or post!=5288 or len(records)!=5288: raise ProofError("Init count")
    if trip!=Counter({(1,0,0):4486,(1,1,0):734,(1,1,1):68}): raise ProofError("child pattern")
    if soreq!=Counter({"FormAnimator.ReqBasicAnm":585,"FormAnimator.ReqSlotAnm":217}): raise ProofError("SO request split")
    if smreq!=Counter({"FormAnimator.ReqBasicAnm":68}): raise ProofError("SOM request split")
    witness="".join("\t".join(map(str,r))+"\n" for r in records).encode("ascii")
    wsha=hashlib.sha256(witness).hexdigest()
    if wsha!=WITNESS_SHA: raise ProofError("witness SHA "+wsha)
    return {"r6_sha256":got,"event_trace_sha256":EVENT_SHA,"record_count":len(records),"witness_byte_count":len(witness),"witness_sha256":wsha}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--r6",required=True); ap.add_argument("--out")
    a=ap.parse_args()
    try:
        result={"dll":verify_dll(a.dll),"r6":verify_r6(a.r6)}
        if a.out: Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(result,indent=2,sort_keys=True)); print("PROVE_INIT_ANIMATION_CLOSURE: PASS"); return 0
    except (OSError,ValueError,KeyError,zipfile.BadZipFile,ProofError) as e:
        print("PROVE_INIT_ANIMATION_CLOSURE: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
