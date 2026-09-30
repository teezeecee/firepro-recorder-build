#!/usr/bin/env python3
import argparse,hashlib,struct,json
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
M={
 "IntRange":(0x002B107D,30,"d6ed5dd5c1cdf595ca459ddc1c740ce66543e9630786cfdc9bf3404247f643f6"),
 "FloatRange":(0x002B109C,30,"088e4cd8eb7a187b28b71251188f91e260b6c7189cf32a45b89f6cd38b1868dc"),
 "Rate100":(0x002AFD54,38,"6899b69e72e4f0b5853a85c1cb3796e28442d2abbd4ca2378d72dd59ce7bba58"),
 "CriticalCheck":(0x002AEC54,678,"8df067018ec4101a6f4861d7fe438f0ea51a2b50b1f698a9b908698e72352466")
}
class ProofError(RuntimeError): pass
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
def f32(c,o,v,l):
    if c[o]!=0x22 or struct.unpack_from("<f",c,o+1)[0]!=struct.unpack("<f",struct.pack("<f",v))[0]:raise ProofError(l)
def verify(path):
    got=sha_path(path)
    if got!=DLL_SHA:raise ProofError("DLL SHA "+got)
    pe=Path(path).read_bytes();ss=sections(pe);cs={}
    for n,(rva,size,sha) in M.items():
        c=mcode(pe,ss,rva)
        if len(c)!=size or hashlib.sha256(c).hexdigest()!=sha:raise ProofError(n+" body")
        cs[n]=c
    for n,last,member in [("IntRange",0x0400578F,0x0A0001EC),("FloatRange",0x04005790,0x0A000804)]:
        c=cs[n]
        tok(c,0x0000,0x7E,0x0400578E,n+" randomCnt load")
        if c[0x0005:0x0007]!=bytes([0x17,0x58]):raise ProofError(n+" increment")
        tok(c,0x0007,0x80,0x0400578E,n+" randomCnt store")
        if c[0x000C:0x000E]!=bytes([0x02,0x03]):raise ProofError(n+" argument forwarding")
        tok(c,0x000E,0x28,member,n+" Unity Range call")
        tok(c,0x0013,0x80,last,n+" last result store")
        tok(c,0x0018,0x7E,last,n+" last result reload")
        if c[0x001D]!=0x2A:raise ProofError(n+" return")
    c=cs["Rate100"]
    if c[0:3]!=bytes([0x16,0x1F,0x64]):raise ProofError("FACT-0025 Range args")
    tok(c,0x0003,0x28,0x0600497B,"FACT-0025 IntRange call")
    c=cs["CriticalCheck"]
    f32(c,0x0288,0.0,"FACT-0022 FloatRange min")
    f32(c,0x028D,1.0,"FACT-0022 FloatRange max")
    tok(c,0x0292,0x28,0x0600497C,"FACT-0022 FloatRange call")
    return {"dll_sha256":got,"methods":{
      "IntRange":{"code_size":len(cs["IntRange"]),"code_sha256":M["IntRange"][2]},
      "FloatRange":{"code_size":len(cs["FloatRange"]),"code_sha256":M["FloatRange"][2]}
    }}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--dll",required=True);ap.add_argument("--out");a=ap.parse_args()
    try:
        r=verify(a.dll)
        if a.out:Path(a.out).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps(r,indent=2,sort_keys=True));print("PROVE_MATCHRANDOM_RANGE_WRAPPERS: PASS");return 0
    except (OSError,ValueError,ProofError) as e:
        print("PROVE_MATCHRANDOM_RANGE_WRAPPERS: FAIL");print(str(e));return 1
if __name__=="__main__":raise SystemExit(main())
