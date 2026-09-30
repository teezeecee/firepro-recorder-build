#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from collections import Counter
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
RVA=0x002DA296
CODE_SIZE=38
CODE_SHA="091053ea365ad855884dd6f93314dd5e1de23bda1c848c291fd2df4d8776d0b2"
WITNESS_SHA="deafacce031d382aacfde3a1fdb8c7f03bd1bcc8559a70156d613a0d23c6a9a5"

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
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\0\0": raise ProofError("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0]; osz=struct.unpack_from("<H",pe,q+20)[0]; s=q+24+osz
    out=[]
    for i in range(n):
        o=s+i*40; vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); out.append((va,vs,rp,rs))
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
    if code[off]!=op or struct.unpack_from("<I",code,off+1)[0]!=t: raise ProofError(label)

def verify_dll(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes(); ss=sections(pe); code=mcode(pe,ss,RVA)
    if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError("method body")
    if code[0:6]!=bytes.fromhex("0203050e0417"): raise ProofError("ReqSlot args")
    tok(code,0x0006,0x28,0x06004E70,"ReqSlotAnm")
    if code[0x000B]!=0x02 or code[0x000C]!=0x02: raise ProofError("CurrentSkill receiver")
    tok(code,0x000D,0x7B,0x04005ECE,"plObj")
    if code[0x0012]!=0x03 or code[0x0013]!=0x16: raise ProofError("GetSkillData args")
    tok(code,0x0014,0x6F,0x06004EB2,"GetSkillData_Equip")
    tok(code,0x0019,0x7D,0x04005ED0,"CurrentSkill")
    if code[0x001E]!=0x02 or code[0x001F]!=0x04: raise ProofError("StartAnm args")
    tok(code,0x0020,0x28,0x06004E75,"StartAnm")
    if code[0x0025]!=0x2A: raise ProofError("ret")
    return {"dll_sha256":got,"code_sha256":CODE_SHA,"code_size":len(code)}

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
        stack=[]; records=[]; pre=post=0; parents=Counter(); slotc=Counter(); bankc=Counter(); revc=Counter()
        with z.open(name) as raw:
            rd=csv.DictReader(io.TextIOWrapper(raw,encoding="utf-8-sig",newline=""),delimiter="\t")
            for line,row in enumerate(rd,start=2):
                ph=row["phase"]
                if ph=="PRE":
                    node={"line":line,"row":dict(row),"children":[],"parent":stack[-1] if stack else None,"post":None,"post_line":None}
                    if stack: stack[-1]["children"].append(node)
                    stack.append(node)
                    if row["method"]=="FormAnimator.StartSlotAnm_Immediately": pre+=1
                elif ph=="POST":
                    if not stack: raise ProofError("POST without PRE")
                    node=stack.pop()
                    if node["row"]["method"]!=row["method"] or node["row"]["instance"]!=row["instance"]: raise ProofError("non-LIFO")
                    node["post"]=dict(row); node["post_line"]=line
                    if row["method"]!="FormAnimator.StartSlotAnm_Immediately": continue
                    post+=1; r=node["row"]; p=node["parent"]; pm=p["row"]["method"] if p else "ROOT"; pl=p["line"] if p else 0
                    parents[pm]+=1
                    a=[x.strip() for x in r["args"].split("|")]
                    if len(a)!=4: raise ProofError("parent args")
                    slotc[a[0]]+=1; bankc[a[1]]+=1; revc[a[2]]+=1
                    req=[x for x in node["children"] if x["row"]["method"]=="FormAnimator.ReqSlotAnm"]
                    st=[x for x in node["children"] if x["row"]["method"]=="FormAnimator.StartAnm"]
                    if len(node["children"])!=2 or len(req)!=1 or len(st)!=1: raise ProofError("child sequence")
                    if [x["row"]["method"] for x in node["children"]]!=["FormAnimator.ReqSlotAnm","FormAnimator.StartAnm"]: raise ProofError("child order")
                    q=req[0]; s=st[0]; qa=[x.strip() for x in q["row"]["args"].split("|")]
                    if qa!=[a[0],a[2],a[3],"True"]: raise ProofError("ReqSlot bridge")
                    if s["row"]["args"]!=a[1]: raise ProofError("StartAnm bridge")
                    if a[3]!=r["target"] or a[3]!=q["row"]["target"]: raise ProofError("target bridge")
                    if q["post"]["ResolvedSkillID"]!=s["row"]["ResolvedSkillID"] or q["post"]["ResolvedSkillID"]!=row["ResolvedSkillID"]: raise ProofError("ResolvedSkillID bridge")
                    if q["post"]["ResolvedSkillSource"]!=s["row"]["ResolvedSkillSource"]: raise ProofError("ResolvedSkillSource bridge")
                    if q["post"]["ResolvedSkillSource"]!="ReqSlotAnm.owner_slot": raise ProofError("ResolvedSkillSource value")
                    if row["SkillSlotID"]!=a[0] or row["bank"]!=a[1] or row["AnmHostPlayer"]!=r["owner_slot"]: raise ProofError("post snapshot")
                    records.append((node["line"],line,pm,pl,q["line"],q["post_line"],s["line"],s["post_line"],a[0],a[1],a[2],a[3],r["owner_slot"],r["target"],q["post"]["ResolvedSkillID"],q["post"]["ResolvedSkillSource"]))
        if stack: raise ProofError("unterminated trace")
    if pre!=36 or post!=36 or len(records)!=36: raise ProofError("call count")
    if parents!=Counter({"Player.PostprocessEachState":32,"ROOT":4}): raise ProofError("parents")
    if slotc!=Counter({"ExchangeOfStriking":32,"ExchangeOfStriking_Performance":2,"ExchangeOfStriking_Finish":2}): raise ProofError("slot values")
    if bankc!=Counter({"4":26,"0":4,"8":4,"2":2}) or revc!=Counter({"True":36}): raise ProofError("bank/rev")
    witness="".join("\t".join(map(str,r))+"\n" for r in records).encode("ascii")
    wsha=hashlib.sha256(witness).hexdigest()
    if len(witness)!=4822 or wsha!=WITNESS_SHA: raise ProofError(f"witness {len(witness)} {wsha}")
    return {"r6_sha256":got,"event_trace_sha256":esha,"record_count":len(records),"witness_byte_count":len(witness),"witness_sha256":wsha}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--r6",required=True); ap.add_argument("--out"); a=ap.parse_args()
    try:
        result={"dll":verify_dll(a.dll),"r6":verify_r6(a.r6)}
        if a.out: Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(result,indent=2,sort_keys=True)); print("PROVE_START_SLOT_ANM_IMMEDIATE_CLOSURE: PASS"); return 0
    except (OSError,ValueError,KeyError,zipfile.BadZipFile,ProofError) as e:
        print("PROVE_START_SLOT_ANM_IMMEDIATE_CLOSURE: FAIL"); print(str(e)); return 1

if __name__=="__main__": raise SystemExit(main())
