#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0032567D
SIZE=13
CODE_SHA="62a68c749da17a7c536b2ef155fd300637ffd8bd582da8979c28fdd87bf83d1c"
CALLER_RVA=0x003229E0
CALLER_SHA="5ba3bf95e0ffa2db0c9766a6254c9016dab003ed26d580ec573effd8e2966b51"
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
 if c[0]!=0x02:raise E("this #1")
 tok(c,0x0001,0x28,0x060052E6,"SongEnd")
 if c[0x0006]!=0x02:raise E("this #2")
 tok(c,0x0007,0x28,0x0A0000D0,"UnityEngine.Object.Destroy")
 if c[0x000C]!=0x2A:raise E("ret")
 tok(cc,0x0023,0x6F,0x060052CA,"FACT-0123 caller")
 print("PROVE_U_AUDIO_DESTROY_AUDIO_PLAYER: PASS")
if __name__=="__main__":main()
