#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0032568B
SIZE=7
CODE_SHA="f0eb7b6d2625782d43a08476d93acb464e82bc45c00d660925f2176d82bc8c4b"
CALLER_RVA=0x003259C8
CALLER_SHA="3ff6f18fdb7ed86c92f309f6496f6d7fc3a7cee75b55c9174345fac0efaeee4c"
class E(RuntimeError):pass
def sections(pe):
 q=struct.unpack_from("<I",pe,0x3c)[0]
 if pe[q:q+4]!=b"PE\\0\\0":raise E("not PE")
 n=struct.unpack_from("<H",pe,q+6)[0];z=struct.unpack_from("<H",pe,q+20)[0];s=q+24+z;out=[]
 for i in range(n):
  o=s+i*40;vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8);out.append((va,max(vs,rs),rp))
 return out
def body(pe,ss,rva):
 for va,sz,rp in ss:
  if va<=rva<va+sz:o=rp+rva-va;break
 else:raise E("rva")
 b=pe[o]
 if b&3==2:return pe[o+1:o+1+(b>>2)]
 fs=struct.unpack_from("<H",pe,o)[0];h=(fs>>12)*4;n=struct.unpack_from("<I",pe,o+4)[0]
 return pe[o+h:o+h+n]
def tok(c,o,op,t,l):
 if c[o]!=op or struct.unpack_from("<I",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,RVA);cc=body(pe,ss,CALLER_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0]!=0x02:raise E("this")
 tok(c,0x0001,0x7B,0x040087E7,"_sendPlaybackState")
 if c[0x0006]!=0x2A:raise E("ret")
 tok(cc,0x005A,0x28,0x060052CB,"FACT-0126 getter #1")
 tok(cc,0x0065,0x28,0x060052CB,"FACT-0126 getter #2")
 print("PROVE_U_AUDIO_GET_SEND_PLAYBACK_STATE: PASS")
if __name__=="__main__":main()
