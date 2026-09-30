#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from collections import Counter
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
R6_SHA="93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d"
EVENT_SHA="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
PRE_RVA=0x002DB11C
PRE_SIZE=1149
PRE_SHA="3dd3f334be363345a7de654b8a11ec29207937ba4dc5bbbba6e2f95eddd1ac9c"
START_RVA=0x002DAA54
START_SIZE=328
START_SHA="aa80c075f247570daf6d74d8d5d7140022160f98a0d3b6233cd7268236a69c94"
WITNESS_SHA="ccb5f70b041db4574dd710212922c4d233dcf24c28d168ddf9518fcdb1d67919"

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

def ldc_i4_value(code,off):
    b=code[off]
    if b==0x15:return -1
    if 0x16<=b<=0x1e:return b-0x16
    if b==0x1f:return struct.unpack_from("<b",code,off+1)[0]
    if b==0x20:return struct.unpack_from("<i",code,off+1)[0]
    raise ProofError(f"not ldc.i4 at {off:#x}")

def verify_dll(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes(); ss=sections(pe)
    pre=mcode(pe,ss,PRE_RVA); start=mcode(pe,ss,START_RVA)
    if len(pre)!=PRE_SIZE or hashlib.sha256(pre).hexdigest()!=PRE_SHA: raise ProofError("PreprocessEachAnm body")
    if len(start)!=START_SIZE or hashlib.sha256(start).hexdigest()!=START_SHA: raise ProofError("StartAnm body")

    tok(pre,0x0000,0x7E,0x040061FA,"PlayerMan.inst")
    tok(pre,0x0006,0x7B,0x04005ECE,"plObj")
    tok(pre,0x000B,0x7B,0x04005FB1,"TargetPlIdx")
    tok(pre,0x0010,0x6F,0x06005065,"GetPlObj")
    tok(pre,0x0017,0x7B,0x04005ED0,"CurrentSkill")
    tok(pre,0x001C,0x7B,0x04007C7A,"anmData")
    tok(pre,0x0022,0x7B,0x04005ED1,"CurrentAnmIdx")
    if pre[0x0027]!=0x9A: raise ProofError("ldelem.ref")
    tok(pre,0x0028,0x7B,0x04007C9D,"anmStartState")
    if pre[0x002E]!=0x07 or pre[0x002F]!=0x17 or pre[0x0030]!=0x59 or pre[0x0031]!=0x45:
        raise ProofError("selector/switch prefix")
    n=struct.unpack_from("<I",pre,0x0032)[0]
    if n!=20: raise ProofError("switch count")
    base=0x0036+4*n
    ds=struct.unpack_from("<"+"i"*n,pre,0x0036)
    targets=[base+d for d in ds]
    expected=[0x008B,0x0116,0x00EC,0x0140,0x01B4,0x01DF,0x026C,0x0297,0x0324,0x034F,0x0152,0x02C2,0x037A,0x038C,0x039E,0x041D,0x020A,0x0432,0x045B,0x046C]
    if targets!=expected: raise ProofError("switch targets")
    if pre[0x0086]!=0x38 or 0x008B+struct.unpack_from("<i",pre,0x0087)[0]!=0x047C:
        raise ProofError("default branch")

    change_sites=[
        (0x00D4,0x00D6,22),(0x00FE,0x0100,22),(0x0128,0x012A,22),(0x0146,0x0148,34),
        (0x019B,0x019D,22),(0x01F1,0x01F3,22),(0x0253,0x0255,22),(0x027E,0x0280,22),
        (0x02A9,0x02AB,22),(0x030B,0x030D,22),(0x0336,0x0338,22),(0x0361,0x0363,22),
        (0x0380,0x0382,36),(0x0392,0x0394,35),(0x03A4,0x03A6,38),(0x019B,0x019D,22)
    ]
    # The list above intentionally repeats neither a distinct call nor a case; replace with exact sorted sites below.
    change_sites=[
        (0x00D4,0x00D6,22),(0x00FE,0x0100,22),(0x0128,0x012A,22),(0x0146,0x0148,34),
        (0x019B,0x019D,22),(0x01F1,0x01F3,22),(0x0253,0x0255,22),(0x027E,0x0280,22),
        (0x02A9,0x02AB,22),(0x030B,0x030D,22),(0x0336,0x0338,22),(0x0361,0x0363,22),
        (0x0380,0x0382,36),(0x0392,0x0394,35),(0x03A4,0x03A6,38),(0x00D4,0x00D6,22)
    ]
    # Verify the 16 actual call offsets directly and their immediately preceding constants.
    actual=[(0x00D6,22),(0x0100,22),(0x012A,22),(0x0148,34),(0x019D,22),(0x01C8,22),(0x01F3,22),(0x0255,22),
            (0x0280,22),(0x02AB,22),(0x030D,22),(0x0338,22),(0x0363,22),(0x0382,36),(0x0394,35),(0x03A6,38)]
    for call_off,val in actual:
        # constants are 2 bytes for these values: ldc.i4.s <value>
        if pre[call_off-2]!=0x1F or struct.unpack_from("<b",pre,call_off-1)[0]!=val:
            raise ProofError(f"ChangeState literal {call_off:#x}")
        tok(pre,call_off,0x6F,0x06004EAE,f"ChangeState {call_off:#x}")

    tok(pre,0x041D+6,0x6F,0x06004ECD,"AddBP")
    if struct.unpack_from("<f",pre,0x0424)[0]!=-12288.0: raise ProofError("AddBP constant")
    tok(pre,0x0451,0x6F,0x06004ED8,"SetDownTime")
    tok(pre,0x0472,0x6F,0x06004F1E,"Poisoned")
    tok(start,0x0142,0x28,0x06004E78,"StartAnm -> PreprocessEachAnm")
    return {"dll_sha256":got,"preprocess_code_sha256":PRE_SHA,"start_anm_code_sha256":START_SHA,"switch_targets":targets}

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
        stack=[]; records=[]; start_pre=start_post=0; preprocess_events=0; all_direct=Counter()
        with z.open(name) as raw:
            rd=csv.DictReader(io.TextIOWrapper(raw,encoding="utf-8-sig",newline=""),delimiter="\t")
            for line,row in enumerate(rd,start=2):
                if "PreprocessEachAnm" in row["method"]: preprocess_events+=1
                if row["phase"]=="PRE":
                    node={"line":line,"row":dict(row),"children":[],"post":None,"post_line":None}
                    if stack: stack[-1]["children"].append(node)
                    stack.append(node)
                    if row["method"]=="FormAnimator.StartAnm": start_pre+=1
                elif row["phase"]=="POST":
                    if not stack: raise ProofError("POST without PRE")
                    node=stack.pop()
                    if node["row"]["method"]!=row["method"] or node["row"]["instance"]!=row["instance"]: raise ProofError("non-LIFO")
                    node["post"]=dict(row); node["post_line"]=line
                    if row["method"]!="FormAnimator.StartAnm": continue
                    start_post+=1
                    for ch in node["children"]: all_direct[ch["row"]["method"]]+=1
                    cs=[x for x in node["children"] if x["row"]["method"]=="Player.ChangeState"]
                    if cs:
                        if len(cs)!=1: raise ProofError("multiple ChangeState children")
                        c=cs[0]
                        records.append((node["line"],line,c["line"],c["post_line"],node["row"]["args"],node["row"]["owner_slot"],node["row"]["target"],c["row"]["args"],node["row"]["state"],row["state"],node["row"]["BasicSkillID"],node["row"]["SkillSlotID"],node["row"]["ResolvedSkillID"]))
        if stack: raise ProofError("unterminated trace")
    if preprocess_events!=0: raise ProofError("PreprocessEachAnm unexpectedly traced")
    if start_pre!=5333 or start_post!=5333: raise ProofError("StartAnm count")
    if all_direct!=Counter({"Player.ChangeState":2}): raise ProofError(f"direct children {all_direct}")
    expected=[
        (96086,96089,96087,96088,"0","4","2","Grapple","NormalAnm","Grapple","Grapple_Front","Grapple_A","445"),
        (321684,321687,321685,321686,"0","4","2","Grapple","NormalAnm","Grapple","Grapple_Front","Grapple_A","445")
    ]
    if records!=expected: raise ProofError("raw child records changed")
    witness="".join("\t".join(map(str,r))+"\n" for r in records).encode("utf-8")
    wsha=hashlib.sha256(witness).hexdigest()
    if len(witness)!=172 or wsha!=WITNESS_SHA: raise ProofError(f"witness {len(witness)} {wsha}")
    return {"r6_sha256":got,"event_trace_sha256":esha,"start_anm_count":start_pre,"change_state_child_count":len(records),"witness_sha256":wsha}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--r6",required=True); ap.add_argument("--out"); a=ap.parse_args()
    try:
        result={"dll":verify_dll(a.dll),"r6":verify_r6(a.r6)}
        if a.out: Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(result,indent=2,sort_keys=True)); print("PROVE_PREPROCESS_EACH_ANM: PASS"); return 0
    except (OSError,ValueError,KeyError,zipfile.BadZipFile,ProofError) as e:
        print("PROVE_PREPROCESS_EACH_ANM: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
