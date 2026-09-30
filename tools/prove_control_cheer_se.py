#!/usr/bin/env python3
import argparse,hashlib,json,struct
from pathlib import Path

DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002DED38
CODE_SIZE=225
CODE_SHA="9f48dfc674cd2b0e1bfde5d807f76c9410dfadf6bf13d0e3fe8a1da481dcf6ce"

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
    if len(code)!=CODE_SIZE or hashlib.sha256(code).hexdigest()!=CODE_SHA: raise ProofError("ControlCheerSE body")

    checks=[
      (0x0000,0x7E,0x0400576C,"MatchMain.inst"),
      (0x0007,0x28,0x0A00002A,"Object.op_Implicit #1"),
      (0x0013,0x7B,0x04005FA8,"animator"),
      (0x0018,0x6F,0x06004E7C,"GetCurrentFormDispInfo"),
      (0x001F,0x7B,0x04007CE6,"FormDispInfo.flags"),
      (0x002C,0x7E,0x0400607E,"cheer_lv_tbl"),
      (0x0032,0x7B,0x04005FA8,"animator #2"),
      (0x0037,0x7B,0x04005ED0,"CurrentSkill"),
      (0x003C,0x7B,0x04007C74,"cheerLevel"),
      (0x0044,0x7B,0x04006058,"isCriticalMove"),
      (0x0058,0x7B,0x04006059,"isSpecialMove"),
      (0x006B,0x7E,0x040061FA,"PlayerMan.inst"),
      (0x0071,0x7B,0x04005FB1,"TargetPlIdx"),
      (0x0076,0x6F,0x06005065,"GetPlObj"),
      (0x007D,0x28,0x0A00002A,"Object.op_Implicit #2"),
      (0x0089,0x7B,0x04005FB3,"target WresParam"),
      (0x008E,0x7B,0x0400108E,"target wrestlerRank"),
      (0x0094,0x7B,0x04005FB3,"host WresParam"),
      (0x0099,0x7B,0x0400108E,"host wrestlerRank"),
      (0x00B8,0x7E,0x040054C9,"Audience.inst check"),
      (0x00BE,0x28,0x0A00000F,"Object.op_Inequality"),
      (0x00C8,0x7E,0x040054C9,"Audience.inst call1"),
      (0x00CF,0x6F,0x060047DA,"PlayLoopCheerVoice"),
      (0x00D4,0x7E,0x040054C9,"Audience.inst call2"),
      (0x00DB,0x6F,0x060047D9,"PlayCheerVoice")
    ]
    for x in checks: tok(code,*x)

    branches=[
      (0x000C,0x3A,0x0012),
      (0x0026,0x3A,0x002C),
      (0x0049,0x39,0x0057),
      (0x0052,0x38,0x00A3),
      (0x005D,0x39,0x006B),
      (0x0066,0x38,0x00A3),
      (0x0082,0x39,0x00A3),
      (0x00A5,0x3D,0x00AB),
      (0x00B1,0x3E,0x00B8),
      (0x00C3,0x39,0x00E0)
    ]
    for off,op,target in branches:
        if code[off]!=op or branch_target(code,off)!=target: raise ProofError(f"branch {off:#x}")

    if code[0x0024:0x0026]!=bytes([0x18,0x5F]): raise ProofError("flags mask 2")
    if code[0x0041]!=0x94: raise ProofError("cheer table ldelem.i4")
    if code[0x004F:0x0052]!=bytes([0x18,0x58,0x0C]): raise ProofError("critical +2")
    if code[0x0063:0x0066]!=bytes([0x17,0x58,0x0C]): raise ProofError("special +1")
    if code[0x009E:0x00A2]!=bytes([0x59,0x18,0x5B,0x58]): raise ProofError("rank delta /2 +")
    if code[0x00AB:0x00AF]!=bytes([0x08,0x17,0x59,0x0C]): raise ProofError("positive level minus1")
    if code[0x00B0]!=0x1A or code[0x00B6:0x00B8]!=bytes([0x1A,0x0C]): raise ProofError("cap 4")
    if code[0x00CD:0x00CF]!=bytes([0x08,0x16]): raise ProofError("PlayLoop args")
    if code[0x00D9:0x00DB]!=bytes([0x1B,0x08]): raise ProofError("PlayCheer args")
    if code[0x00E0]!=0x2A: raise ProofError("ret")
    return {"dll_sha256":got,"code_size":len(code),"code_sha256":CODE_SHA}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dll",required=True); ap.add_argument("--out"); a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out: Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True)); print("PROVE_CONTROL_CHEER_SE: PASS"); return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_CONTROL_CHEER_SE: FAIL"); print(str(e)); return 1
if __name__=="__main__": raise SystemExit(main())
