#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0005F840
SIZE=143
CODE_SHA="e71bcaa68daa57d26a04e13b1d43b7761db94df3724f312e48ce26b7d81e5442"
CALLER_RVA=0x0005F7DC
CALLER_SHA="1aef92c709ae4ad954e979dec831bd361ef6546059f6ddf914fe9fa352bae5cc"
VALUES=[758160,775630,912460,1037890,766550,1104260,1121430,1120550,1120540,1191160,1191161,1191162,3932720]
TARGETS=[0x003F,0x0045,0x004B,0x0051,0x0057,0x005D,0x0063,0x0069,0x006F,0x0075,0x007B,0x0081,0x0087]
class E(RuntimeError): pass
def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\\0\\0": raise E("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0]; z=struct.unpack_from("<H",pe,q+20)[0]
    s=q+24+z; out=[]
    for i in range(n):
        o=s+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        out.append((va,max(vs,rs),rp))
    return out
def method(pe,ss,rva):
    for va,sz,rp in ss:
        if va<=rva<va+sz:
            o=rp+rva-va; break
    else: raise E("rva")
    b=pe[o]
    if b&3==2:
        n=b>>2
        return {"flags":2,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+n]}
    fs=struct.unpack_from("<H",pe,o)[0]
    h=(fs>>12)*4; n=struct.unpack_from("<I",pe,o+4)[0]
    return {"flags":fs&0x0FFF,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,label):
    if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t: raise E(label)
def main():
    a=argparse.ArgumentParser(); a.add_argument("--dll",required=True); x=a.parse_args()
    pe=Path(x.dll).read_bytes()
    if hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E("dll")
    ss=sections(pe); m=method(pe,ss,RVA); c=m["code"]; caller=method(pe,ss,CALLER_RVA)["code"]
    if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA: raise E("body")
    if m["flags"]!=0x0013 or m["max_stack"]!=1 or m["local_sig"]!=0: raise E("header")
    if hashlib.sha256(caller).hexdigest()!=CALLER_SHA: raise E("caller")
    if c[0]!=0x02 or c[1]!=0x45 or struct.unpack_from("<I",c,2)[0]!=13: raise E("switch header")
    base=0x003A
    targets=[base+struct.unpack_from("<i",c,6+4*i)[0] for i in range(13)]
    if targets!=TARGETS: raise E("switch targets")
    if c[0x003A]!=0x38 or 0x003F+struct.unpack_from("<i",c,0x003B)[0]!=0x008D: raise E("default branch")
    got=[]
    for t in TARGETS:
        if c[t]!=0x20 or c[t+5]!=0x2A: raise E("case encoding")
        got.append(struct.unpack_from("<i",c,t+1)[0])
    if got!=VALUES: raise E("case values")
    if c[0x008D:0x008F]!=bytes([0x15,0x2A]): raise E("default -1")
    tok(caller,0x0001,0x28,0x06001036,"FACT-0120 caller")
    print("PROVE_DLC_CHECKER_GET_DLC_ID: PASS")
if __name__=="__main__": main()
