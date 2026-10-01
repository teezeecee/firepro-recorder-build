#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003229E0
SIZE=59
CODE_SHA="5ba3bf95e0ffa2db0c9766a6254c9016dab003ed26d580ec573effd8e2966b51"
CALLER_RVA=0x002A96A8
CALLER_SHA="ce8a2a91a564c9f28928b39c7d444dfe0758d3b771b7a142125e5bac4daaa2b5"
class E(RuntimeError): pass
def sections(pe):
    q=struct.unpack_from("<I",pe,0x3c)[0]
    if pe[q:q+4]!=b"PE\\0\\0": raise E("not PE")
    n=struct.unpack_from("<H",pe,q+6)[0]; z=struct.unpack_from("<H",pe,q+20)[0]
    s=q+24+z; out=[]
    for i in range(n):
        o=s+i*40; vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
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
    if m["flags"]!=0x0013 or m["max_stack"]!=2 or m["local_sig"]!=0x1100120B: raise E("header")
    if hashlib.sha256(caller).hexdigest()!=CALLER_SHA: raise E("caller")
    tok(c,0x0000,0x7E,0x040086EB,"audioSrcInfo")
    if c[0x0005:0x0009]!=bytes([0x16,0x9A,0x0A,0x06]): raise E("audioSrcInfo[0]")
    tok(c,0x0009,0x6F,0x060052C4,"AudioSrcInfo.Stop")
    tok(c,0x000E,0x7E,0x04008709,"script_uAudioPlayer #1")
    if c[0x0013]!=0x14: raise E("null #1")
    tok(c,0x0014,0x28,0x0A00000F,"Object inequality")
    if c[0x0019]!=0x39 or 0x001E+struct.unpack_from("<i",c,0x001A)[0]!=0x002E: raise E("null branch")
    tok(c,0x001E,0x7E,0x04008709,"script_uAudioPlayer #2")
    tok(c,0x0023,0x6F,0x060052CA,"Destroy_AudioPlayer")
    if c[0x0028]!=0x14: raise E("null #2")
    tok(c,0x0029,0x80,0x04008709,"script_uAudioPlayer clear")
    if c[0x002E]!=0x16: raise E("zero frm")
    tok(c,0x002F,0x80,0x040086F7,"bgmFadeOutFrm")
    if c[0x0034]!=0x16: raise E("zero cnt")
    tok(c,0x0035,0x80,0x040086F6,"bgmFadeOutCnt")
    if c[0x003A]!=0x2A: raise E("ret")
    tok(caller,0x0130,0x28,0x060052A4,"FACT-0122 caller")
    print("PROVE_MENU_SOUND_STOP_BGM: PASS")
if __name__=="__main__": main()
