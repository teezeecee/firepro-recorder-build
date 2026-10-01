#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x0032587C
SIZE=8
CODE_SHA="bf7afe343990f70067b2d0a5f418a180d7f1abee664827c4b4e6e18940403ca7"
CALLER_RVA=0x00323130
CALLER_SHA="e84b8a91478acffadf8ee5f39f17855e421d0cf1b4d482f97dfbb53700440a5a"
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
 if c[0:2]!=bytes([0x02,0x03]):raise E("this/volumeIN")
 tok(c,0x0002,0x28,0x060052DC,"set_Volume")
 if c[0x0007]!=0x2A:raise E("ret")
 tok(cc,0x0105,0x6F,0x060052E0,"FACT-0133 ChangeCurrentVolume #1")
 tok(cc,0x01BC,0x6F,0x060052E0,"FACT-0133 ChangeCurrentVolume #2")
 print("PROVE_U_AUDIO_CHANGE_CURRENT_VOLUME: PASS")
if __name__=="__main__":main()
