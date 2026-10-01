#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003254A4
SIZE=7
CODE_SHA="5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9"
FACT0144_RVA=0x00323320
FACT0144_SHA="8b924ec5650c79c888696f801976f2f99b92a71ba35fb44d7fcabce6d6e4c799"
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
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,RVA);p=body(pe,ss,FACT0144_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(p).hexdigest()!=FACT0144_SHA:raise E("FACT-0144 body")
 if c[0]!=0x02 or c[1]!=0x28 or struct.unpack_from("<I",c,2)[0]!=0x0A0000EF or c[6]!=0x2A:raise E("Object ctor flow")
 if p[0]!=0x73 or struct.unpack_from("<I",p,1)[0]!=0x0600750E:raise E("FACT-0144 newobj")
 print("PROVE_MENU_SOUND_MY_MUSIC_PLAY_CO_CTOR: PASS")
if __name__=="__main__":main()
