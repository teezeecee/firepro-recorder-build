#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x003237F5
SIZE=8
CODE_SHA="5c1fa2fbc6a929b6fffb5ebb0e04fae4d1fa8b86b4d1984529906b46d8824dd0"
CALLER_RVA=0x00322268
CALLER_SHA="2e0905ada32d6f97c3a3ac37f28bb0722b6084a109618070cf1dfc1ea1fb4733"
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
 if c[0x0000:0x0002]!=bytes([0x02,0x03]):raise E("this/clip")
 tok(c,0x0002,0x7D,0x0400874B,"AudioClipInfo.audioClip")
 if c[0x0007]!=0x2A:raise E("ret")
 for off in (0x00FF,0x0142,0x0172):tok(cc,off,0x6F,0x060052C2,"FACT-0111 AudioClipInfo.Set")
 if cc[0x00FB:0x00FE]!=bytes([0x1F,0x21,0x9A]):raise E("raw33 #1")
 if cc[0x013D:0x0140]!=bytes([0x1F,0x21,0x9A]):raise E("raw33 #2")
 if cc[0x016D:0x0170]!=bytes([0x1F,0x21,0x9A]):raise E("raw33 #3")
 print("PROVE_AUDIO_CLIP_INFO_SET: PASS")
if __name__=="__main__":main()
