#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002DB890
CODE_SIZE=738
CODE_SHA="1e18c732ea0674fae8fdecc0b0d06fc976ec4494df663156925e99c4485b4c00"

class ProofError(RuntimeError): pass

def sha_path(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
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

def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes(); code=mcode(pe,sections(pe),RVA)
    if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError("UpdateAnimation body")

    checks=[
      (0x0010,0x6F,0x06005065,"GetPlObj"),
      (0x0017,0x7B,0x04005EE7,"isAnmPause"),
      (0x0028,0x6F,0x06004EBE,"ProcessFoxSleep"),
      (0x002E,0x7B,0x04005EEC,"reqAnmInit read"),
      (0x0039,0x28,0x06004E73,"InitAnimation"),
      (0x0040,0x7D,0x04005EEC,"reqAnmInit clear"),
      (0x00A6,0x28,0x06005074,"GetPlayerStatusData"),
      (0x00AD,0x7B,0x04006268,"anmLoop"),
      (0x00BA,0x7D,0x04005ED5,"currentFormIdx reset"),
      (0x00C1,0x7D,0x04005EE8,"isAnmSync"),
      (0x00D2,0x28,0x06004E74,"ProcessAnmLoop"),
      (0x00F7,0x7B,0x04007C9F,"formDispList"),
      (0x00FE,0x7B,0x04007CDC,"dispFrm scan"),
      (0x0136,0x28,0x06004E7C,"GetCurrentFormDispInfo"),
      (0x0140,0x7B,0x04007CDC,"dispFrm current"),
      (0x014C,0x7D,0x04005ED4,"FormDispDuration store"),
      (0x0153,0x7C,0x04007CD8,"centerPos x"),
      (0x0161,0x7C,0x04007CD8,"centerPos y"),
      (0x0174,0x7B,0x04005FB0,"PlDir"),
      (0x018A,0x7C,0x04005FAA,"PlPos x address"),
      (0x01A9,0x7C,0x04005FAA,"PlPos y address"),
      (0x01C5,0x7B,0x04007CE6,"flags"),
      (0x01CA,0x7D,0x04005EDD,"FormRev"),
      (0x01D0,0x28,0x06004E7D,"PlayAnimationSE"),
      (0x01EF,0x7D,0x04005ED7,"AnmHostPlayer"),
      (0x020D,0x7B,0x04005FEE,"Zone"),
      (0x0222,0x7B,0x04007CE5,"ringVibration"),
      (0x0235,0x6F,0x060050E1,"ShakeRing"),
      (0x025F,0x28,0x0600494D,"ApplyDamage"),
      (0x0270,0x6F,0x06004F0D,"target CalcDownTime"),
      (0x028A,0x7B,0x0400602F,"plCont_AI"),
      (0x028F,0x6F,0x0600500B,"EndPriAct"),
      (0x029A,0x6F,0x06004F0E,"ApplySuicideDamage"),
      (0x02A5,0x6F,0x06004F0D,"host CalcDownTime"),
      (0x02B0,0x6F,0x06004EBF,"ControlCheerSE"),
      (0x02B6,0x7B,0x04005EE0,"AnmStopTimer read"),
      (0x02C9,0x7D,0x04005EE0,"AnmStopTimer store"),
      (0x02D5,0x7B,0x04005ED4,"FormDispDuration tail read"),
      (0x02DC,0x7D,0x04005ED4,"FormDispDuration tail store"),
    ]
    for x in checks: tok(code,*x)

    if code[0x0197]!=0x22 or struct.unpack_from("<f",code,0x0198)[0]!=struct.unpack("<f",struct.pack("<f",0.0208333320915699))[0]:
        raise ProofError("x position scale")
    if code[0x01B6]!=0x22 or struct.unpack_from("<f",code,0x01B7)[0]!=struct.unpack("<f",struct.pack("<f",0.0208333320915699))[0]:
        raise ProofError("y position scale")
    if code[0x01DC]!=0x1A or code[0x01DD]!=0x5F: raise ProofError("flags mask 4")
    if code[0x0241:0x0244]!=bytes([0x1F,0x20,0x5F]): raise ProofError("flags mask 32")
    if code[0x027C:0x027F]!=bytes([0x1F,0x10,0x5F]): raise ProofError("flags mask 16")
    if code[0x02C7]!=0x17 or code[0x02C8]!=0x59 or code[0x02DA]!=0x17 or code[0x02DB]!=0x59:
        raise ProofError("timer decrement")
    if code[0x02E1]!=0x2A: raise ProofError("ret")
    return {"dll_sha256":got,"code_size":len(code),"code_sha256":CODE_SHA}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--out"); a=ap.parse_args()
    try:
        result=verify(a.dll)
        if a.out: Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(result,indent=2,sort_keys=True)); print("PROVE_UPDATE_ANIMATION_FULL: PASS"); return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_UPDATE_ANIMATION_FULL: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
