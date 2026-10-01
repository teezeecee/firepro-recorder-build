#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0005F7DC
SIZE=39
CODE_SHA="1aef92c709ae4ad954e979dec831bd361ef6546059f6ddf914fe9fa352bae5cc"
CALLER_RVA=0x00316C6C
CALLER_SHA="d353bf6e7046434074ecca1c5a62cb8cd9ec636500659fc5b9083f2943c7d841"
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
def locate(ss,rva):
    for va,sz,rp in ss:
        if va<=rva<va+sz: return rp+rva-va
    raise E("rva")
def method(pe,ss,rva):
    o=locate(ss,rva); b=pe[o]
    if b&3==2:
        n=b>>2
        return {"offset":o,"flags":2,"header":1,"max_stack":8,"local_sig":0,"code":pe[o+1:o+1+n]}
    fs=struct.unpack_from("<H",pe,o)[0]
    h=(fs>>12)*4; n=struct.unpack_from("<I",pe,o+4)[0]
    return {"offset":o,"flags":fs&0x0FFF,"header":h,"max_stack":struct.unpack_from("<H",pe,o+2)[0],"local_sig":struct.unpack_from("<I",pe,o+8)[0],"code":pe[o+h:o+h+n]}
def tok(c,o,op,t,label):
    if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t: raise E(label)
def leave(c,o,target,label):
    if c[o]!=0xDD or o+5+struct.unpack_from("<i",c,o+1)[0]!=target: raise E(label)
def main():
    a=argparse.ArgumentParser(); a.add_argument("--dll",required=True); x=a.parse_args()
    pe=Path(x.dll).read_bytes()
    if hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E("dll")
    ss=sections(pe); m=method(pe,ss,RVA); c=m["code"]; caller=method(pe,ss,CALLER_RVA)["code"]
    if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA: raise E("body")
    if m["flags"]!=0x001B or m["header"]!=12 or m["max_stack"]!=2 or m["local_sig"]!=0x110002A5: raise E("header")
    if hashlib.sha256(caller).hexdigest()!=CALLER_SHA: raise E("caller body")
    if c[0]!=0x02: raise E("dlcNum")
    tok(c,0x0001,0x28,0x06001036,"GetDLCID")
    if c[0x0006]!=0x0A: raise E("store local0")
    if c[0x0007:0x000A]!=bytes([0x12,0x01,0x06]): raise E("AppId_t args")
    tok(c,0x000A,0x28,0x0A0006C4,"AppId_t ctor")
    if c[0x000F]!=0x07: raise E("load AppId_t")
    tok(c,0x0010,0x28,0x0A0006C5,"BIsSubscribedApp")
    if c[0x0015:0x0018]!=bytes([0x0C,0x08,0x0D]): raise E("true-path locals")
    leave(c,0x0018,0x0025,"try leave")
    if c[0x001D:0x0020]!=bytes([0x26,0x16,0x0D]): raise E("handler false")
    leave(c,0x0020,0x0025,"handler leave")
    if c[0x0025:0x0027]!=bytes([0x09,0x2A]): raise E("return")
    end=(m["offset"]+m["header"]+len(c)+3)&~3
    sec=pe[end:end+16]
    if sec[0]!=0x01 or sec[1]!=0x10: raise E("EH section header")
    flags,tryoff=struct.unpack_from("<HH",sec,4)
    trylen=sec[8]; handoff=struct.unpack_from("<H",sec,9)[0]; handlen=sec[11]
    catch=struct.unpack_from("<I",sec,12)[0]
    if (flags,tryoff,trylen,handoff,handlen,catch)!=(0,0x000F,14,0x001D,8,0x010000C2): raise E("EH clause")
    tok(caller,0x0001,0x28,0x06001033,"FACT-0119 caller")
    print("PROVE_DLC_CHECKER_IS_OWNER: PASS")
if __name__=="__main__": main()
