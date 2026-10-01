#!/usr/bin/env python3
import argparse,hashlib,struct
from pathlib import Path
DLL_SHA="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
RVA=0x00325776
SIZE=41
CODE_SHA="49f83f2ff33655f9bece0288383a552b4e5a31346d16547fcfd1028ecfdc7b0b"
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
def br(c,o,op,t,l):
 if c[o]!=op or o+5+struct.unpack_from("<i",c,o+1)[0]!=t:raise E(l)
def main():
 a=argparse.ArgumentParser();a.add_argument("--dll",required=True);x=a.parse_args()
 pe=Path(x.dll).read_bytes()
 if hashlib.sha256(pe).hexdigest()!=DLL_SHA:raise E("dll")
 ss=sections(pe);c=body(pe,ss,RVA);cc=body(pe,ss,CALLER_RVA)
 if len(c)!=SIZE or hashlib.sha256(c).hexdigest()!=CODE_SHA:raise E("body")
 if hashlib.sha256(cc).hexdigest()!=CALLER_SHA:raise E("caller")
 if c[0]!=0x02:raise E("backend receiver #1")
 tok(c,0x0001,0x7B,0x040087E3,"_uAudio #1")
 br(c,0x0006,0x39,0x0022,"backend null")
 if c[0x000B]!=0x02:raise E("state receiver")
 tok(c,0x000C,0x7B,0x040087E9,"State")
 br(c,0x0011,0x39,0x0022,"State zero")
 if c[0x0016]!=0x02:raise E("backend receiver #2")
 tok(c,0x0017,0x7B,0x040087E3,"_uAudio #2")
 tok(c,0x001C,0x6F,0x0A000FB8,"backend get_CurrentTime")
 if c[0x0021]!=0x2A:raise E("backend return")
 if c[0x0022]!=0x02:raise E("fallback receiver")
 tok(c,0x0023,0x7B,0x040087F2,"endSongTime")
 if c[0x0028]!=0x2A:raise E("fallback return")
 tok(cc,0x0002,0x28,0x060052D6,"FACT-0126 caller")
 print("PROVE_U_AUDIO_GET_CURRENT_TIME: PASS")
if __name__=="__main__":main()
