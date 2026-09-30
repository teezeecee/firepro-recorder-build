#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002DEC78
CODE_SIZE=177
CODE_SHA="1b6876147c6a2934da2daa0c1ceeaeec1952b91df7391c37ea2521d85157b16f"

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

def branch_target(code,off):
    return off+5+struct.unpack_from("<i",code,off+1)[0]

def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes(); code=mcode(pe,sections(pe),RVA)
    if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError("ProcessFoxSleep body")

    checks=[
      (0x0001,0x7B,0x04006055,"isPossibleFoxSleep"),
      (0x000D,0x7B,0x04005FBE,"FoxSleepCnt gate"),
      (0x001A,0x7B,0x04005FA8,"animator gate 1"),
      (0x001F,0x7B,0x04005EEA,"isAnmBoot"),
      (0x002B,0x7B,0x04005FD0,"StunTime"),
      (0x0038,0x7B,0x04005FA8,"animator gate 2"),
      (0x003D,0x7B,0x04005ED8,"BasicSkillID 89"),
      (0x004A,0x7B,0x04005FA8,"animator gate 3"),
      (0x004F,0x7B,0x04005ED8,"BasicSkillID 90"),
      (0x005D,0x7B,0x04005FA8,"animator gate 4"),
      (0x0062,0x7B,0x04005ED5,"currentFormIdx"),
      (0x006F,0x7B,0x04006023,"padOn"),
      (0x007F,0x7D,0x04006051,"isDisableUpdateDownTime"),
      (0x0085,0x7B,0x04005FA8,"animator effect"),
      (0x008B,0x7B,0x04005ED4,"FormDispDuration load"),
      (0x0092,0x7D,0x04005ED4,"FormDispDuration store"),
      (0x0099,0x7B,0x04005FBE,"FoxSleepCnt load"),
      (0x00A0,0x7D,0x04005FBE,"FoxSleepCnt store"),
      (0x00AB,0x28,0x06004ED1,"ConsumeSP")
    ]
    for x in checks: tok(code,*x)

    branches=[
      (0x0006,0x3A,0x000C),
      (0x0013,0x3D,0x0019),
      (0x0024,0x3A,0x002A),
      (0x0031,0x3E,0x0037),
      (0x0044,0x3B,0x005C),
      (0x0056,0x3B,0x005C),
      (0x0068,0x3B,0x006E),
      (0x0077,0x3A,0x007D),
    ]
    for off,op,target in branches:
        if code[off]!=op or branch_target(code,off)!=target: raise ProofError(f"branch {off:#x}")

    if code[0x0042:0x0044]!=bytes([0x1F,89]): raise ProofError("BasicSkillID 89 literal")
    if code[0x0054:0x0056]!=bytes([0x1F,90]): raise ProofError("BasicSkillID 90 literal")
    if code[0x0067]!=0x1B: raise ProofError("form index literal 5")
    if code[0x0074:0x0077]!=bytes([0x1F,48,0x5F]): raise ProofError("padOn mask 48")
    if code[0x007E]!=0x16 or code[0x0090]!=0x17 or code[0x0091]!=0x58 or code[0x009E]!=0x17 or code[0x009F]!=0x59:
        raise ProofError("effect arithmetic")
    if code[0x00A6]!=0x22 or struct.unpack_from("<f",code,0x00A7)[0]!=4.0: raise ProofError("ConsumeSP float")
    if code[0x00B0]!=0x2A: raise ProofError("ret")
    return {"dll_sha256":got,"code_size":len(code),"code_sha256":CODE_SHA}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--out"); a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out: Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True)); print("PROVE_PROCESS_FOX_SLEEP: PASS"); return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_PROCESS_FOX_SLEEP: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
