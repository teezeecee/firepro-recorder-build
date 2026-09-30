#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x002AFD54
SIZE=38
CODE_SHA="6899b69e72e4f0b5853a85c1cb3796e28442d2abbd4ca2378d72dd59ce7bba58"
class ProofError(RuntimeError): pass
def sha_path(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()
def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\0\0": raise ProofError("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0];osz=struct.unpack_from("<H",pe,q+20)[0];s=q+24+osz;out=[]
    for i in range(n):
        o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,vs,rp,rs))
    return out
def rvaoff(pe,ss,rva):
    for va,vs,rp,rs in ss:
        if va<=rva<va+max(vs,rs): return rp+rva-va
    raise ProofError("RVA unmapped")
def mcode(pe,ss,rva):
    o=rvaoff(pe,ss,rva);b=pe[o]
    if b&3==2: h=1;n=b>>2
    elif b&3==3:
        fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
    else: raise ProofError("bad IL header")
    return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
    if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t: raise ProofError(l)
def bt(c,o): return o+5+struct.unpack_from("<i",c,o+1)[0]
def br(c,o,op,t,l):
    if c[o]!=op or bt(c,o)!=t: raise ProofError(l)
def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA: raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes();c=mcode(pe,sections(pe),RVA)
    if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA: raise ProofError("mRate100Check body")
    if c[0x0000:0x0003]!=bytes([0x16,0x1F,0x64]): raise ProofError("Range integer args 0,100")
    tok(c,0x0003,0x28,0x0600497B,"MatchRandom.Range Int32 overload")
    if c[0x0008]!=0x0A: raise ProofError("stloc.0")
    tok(c,0x0009,0x28,0x06004907,"MatchMain.GetInst")
    if c[0x000E]!=0x14: raise ProofError("ldnull")
    tok(c,0x000F,0x28,0x0A000006,"Object.op_Equality")
    br(c,0x0014,0x39,0x001B,"MatchMain non-null branch")
    if c[0x0019:0x001B]!=bytes([0x16,0x2A]): raise ProofError("null false return")
    if c[0x001B:0x001D]!=bytes([0x02,0x06]): raise ProofError("comparison operand order")
    br(c,0x001D,0x3E,0x0024,"raw ble false branch")
    if c[0x0022:0x0024]!=bytes([0x17,0x2A]): raise ProofError("true return")
    if c[0x0024:0x0026]!=bytes([0x16,0x2A]): raise ProofError("comparison false return")
    return {"dll_sha256":got,"code_size":len(c),"code_sha256":CODE_SHA}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out: Path(a.out).write_text(__import__("json").dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(__import__("json").dumps(r,indent=2,sort_keys=True));print("PROVE_RATE100_CHECK: PASS");return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_RATE100_CHECK: FAIL");print(str(e));return 1
if __name__=="__main__": raise SystemExit(main())
