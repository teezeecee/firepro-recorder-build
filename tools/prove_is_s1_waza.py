#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "IsS1Waza":(0x0031FF75,40,"7693ac0d94e82285e39d223199a9bae9209d6b4f75f765839ddba129cd85fbd0"),
 "CalcDamage":(0x002AE858,1007,"058a61f95c9c59f9e5d3079b2c08a1420599dcec208152325c520e26a5983d04"),
 "CriticalCheck":(0x002AEC54,678,"8df067018ec4101a6f4861d7fe438f0ea51a2b50b1f698a9b908698e72352466")
}
class ProofError(RuntimeError):pass
def sha_path(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for x in iter(lambda:f.read(1024*1024),b""):h.update(x)
    return h.hexdigest()
def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\0\0":raise ProofError("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0];osz=struct.unpack_from("<H",pe,q+20)[0];s=q+24+osz;out=[]
    for i in range(n):
        o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
    return out
def rvaoff(ss,rva):
    for va,sz,rp in ss:
        if va<=rva<va+sz:return rp+rva-va
    raise ProofError("RVA unmapped")
def mcode(pe,ss,rva):
    o=rvaoff(ss,rva);fb=pe[o]
    if fb&3==2:h=1;n=fb>>2
    elif fb&3==3:
        fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
    else:raise ProofError("bad IL header")
    return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
    if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise ProofError(l)
def br(c,o,op,t,l):
    if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise ProofError(l)
def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes();ss=sections(pe);cs={}
    for n,(rva,size,sha) in M.items():
        c=mcode(pe,ss,rva)
        if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+" body")
        cs[n]=c
    c=cs["IsS1Waza"]
    if c[0]!=0x02:raise ProofError("arg0 #1")
    tok(c,0x0001,0x7B,0x04007C51,"skillType #1")
    br(c,0x0006,0x39,0x0024,"raw0 brfalse true")
    if c[0x000B]!=0x02:raise ProofError("arg0 #2")
    tok(c,0x000C,0x7B,0x04007C51,"skillType #2")
    if c[0x0011]!=0x17:raise ProofError("raw1")
    br(c,0x0012,0x3B,0x0024,"raw1 beq true")
    if c[0x0017]!=0x02:raise ProofError("arg0 #3")
    tok(c,0x0018,0x7B,0x04007C51,"skillType #3")
    if c[0x001D:0x001F]!=bytes([0x1F,0x09]):raise ProofError("raw9")
    br(c,0x001F,0x40,0x0026,"raw9 bne false")
    if c[0x0024:0x0028]!=bytes([0x17,0x2A,0x16,0x2A]):raise ProofError("true/false returns")
    tok(cs["CalcDamage"],0x03AD,0x28,0x06005266,"FACT-0021 caller")
    tok(cs["CriticalCheck"],0x0272,0x28,0x06005266,"FACT-0022 caller")
    return {"dll_sha256":got,"method":{"code_size":len(c),"code_sha256":M["IsS1Waza"][2]},"raw_true_values":[0,1,9]}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_IS_S1_WAZA: PASS");return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_IS_S1_WAZA: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
